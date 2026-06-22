package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Configuración básica
const (
	TunnelPort = ":9000" // Puerto para el túnel
	PublicPort = ":8080" // Puerto público para exponer
)

// getEnv devuelve el valor de la variable de entorno o, si no está definida, el default.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Tokens válidos (en producción esto estaría en BD)
var validTokens = map[string]string{
	"token_user1": "user1",
	"token_user2": "user2",
	"demo_token":  "demo",
}

// Estructura para manejar túneles
type Tunnel struct {
	Conn     net.Conn
	User     string
	Subdomain string
	ConnectedAt time.Time
	Requests chan *Request
	mu       sync.Mutex
	pendingRequests map[string]chan *Response
	pendingMu *sync.Mutex
}

type Request struct {
	ID       string
	HTTPReq  *http.Request
	Response chan *Response
}

type Response struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
}

// Protocolo de mensajes
type Message struct {
	Type    string          `json:"type"` // "auth", "request", "response"
	Token   string          `json:"token,omitempty"`
	ReqID   string          `json:"req_id,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

var (
	tunnels = make(map[string]*Tunnel) // subdomain -> tunnel
	mu      sync.RWMutex
)

func authenticateClient(conn net.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	
	// Leer mensaje de autenticación
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return "", err
	}
	
	var msg Message
	if err := json.Unmarshal(line, &msg); err != nil {
		return "", err
	}
	
	if msg.Type != "auth" {
		return "", fmt.Errorf("expected auth message")
	}
	
	// Validar token
	user, valid := validTokens[msg.Token]
	if !valid {
		return "", fmt.Errorf("invalid token")
	}
	
	// Enviar confirmación
	response := Message{Type: "auth_ok"}
	data, _ := json.Marshal(response)
	conn.Write(append(data, '\n'))
	conn.SetReadDeadline(time.Time{})
	
	return user, nil
}

func handleTunnelConnection(conn net.Conn) {
	defer conn.Close()
	
	// Autenticar cliente
	user, err := authenticateClient(conn)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return
	}
	
	subdomain := user // Por simplicidad, subdomain = username
	log.Printf("Tunnel established for user: %s (subdomain: %s)", user, subdomain)
	
	// Crear túnel
	tunnel := &Tunnel{
		Conn:            conn,
		User:            user,
		Subdomain:       subdomain,
		ConnectedAt:     time.Now(),
		Requests:        make(chan *Request, 100),
		pendingRequests: make(map[string]chan *Response),
		pendingMu:       &sync.Mutex{},
	}

	// Registrar túnel
	mu.Lock()
	tunnels[subdomain] = tunnel
	mu.Unlock()

	defer func() {
		mu.Lock()
		delete(tunnels, subdomain)
		mu.Unlock()
		close(tunnel.Requests)
		log.Printf("Tunnel closed for user: %s", user)
	}()

	// Goroutine para enviar requests
	go func() {
		for req := range tunnel.Requests {
			handleTunnelRequest(tunnel, req)
		}
	}()

	// Escuchar respuestas del cliente
	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from tunnel: %v", err)
			}
			return
		}
		
		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			log.Printf("Error parsing message: %v", err)
			continue
		}
		
		if msg.Type == "response" {
			var resp Response
			if err := json.Unmarshal(msg.Data, &resp); err != nil {
				log.Printf("Error parsing response: %v", err)
				continue
			}
			
			tunnel.pendingMu.Lock()
			respChan, exists := tunnel.pendingRequests[msg.ReqID]
			if exists {
				delete(tunnel.pendingRequests, msg.ReqID)
			}
			tunnel.pendingMu.Unlock()
			
			if exists {
				respChan <- &resp
			}
		}
	}
}

func handleTunnelRequest(tunnel *Tunnel, req *Request) {
	// Registrar request pendiente
	tunnel.pendingMu.Lock()
	tunnel.pendingRequests[req.ID] = req.Response
	tunnel.pendingMu.Unlock()
	
	// Enviar request al cliente
	msg := Message{
		Type:  "request",
		ReqID: req.ID,
	}
	
	// Serializar HTTP request
	reqData := map[string]interface{}{
		"method": req.HTTPReq.Method,
		"path":   req.HTTPReq.URL.Path,
		"query":  req.HTTPReq.URL.RawQuery,
		"headers": req.HTTPReq.Header,
	}
	body, _ := io.ReadAll(req.HTTPReq.Body)
	req.HTTPReq.Body.Close()
	reqData["body"] = string(body)
	
	msg.Data, _ = json.Marshal(reqData)
	
	tunnel.mu.Lock()
	data, _ := json.Marshal(msg)
	_, err := tunnel.Conn.Write(append(data, '\n'))
	tunnel.mu.Unlock()
	
	if err != nil {
		log.Printf("Error sending request to tunnel: %v", err)
		req.Response <- &Response{
			StatusCode: 502,
			Body:       "Bad Gateway",
		}
		return
	}
	
	// Esperar respuesta (con timeout)
	select {
	case <-req.Response:
		// Respuesta recibida, nada más que hacer
	case <-time.After(30 * time.Second):
		// Timeout
		tunnel.pendingMu.Lock()
		delete(tunnel.pendingRequests, req.ID)
		tunnel.pendingMu.Unlock()
		
		req.Response <- &Response{
			StatusCode: 504,
			Body:       "Gateway Timeout",
		}
	}
}

// extractSubdomain deriva el subdomain a partir del Host de la request pública,
// no de un header/query controlable por el cliente. Solo acepta un nivel de
// subdomain (sin puntos) bajo baseDomain; cualquier otra cosa se rechaza.
func extractSubdomain(host, baseDomain string) (string, bool) {
	host = strings.Split(host, ":")[0] // descartar el puerto si viene incluido
	suffix := "." + baseDomain
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	sub := strings.TrimSuffix(host, suffix)
	if sub == "" || strings.Contains(sub, ".") {
		return "", false
	}
	return sub, true
}

func handlePublic(w http.ResponseWriter, r *http.Request, baseDomain string) {
	// Determinar subdomain a partir del Host real de la request
	subdomain, ok := extractSubdomain(r.Host, baseDomain)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Host inválido %q, se espera <subdomain>.%s", r.Host, baseDomain)))
		return
	}

	// Buscar túnel
	mu.RLock()
	tunnel, exists := tunnels[subdomain]
	mu.RUnlock()
	
	if !exists {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(fmt.Sprintf("Tunnel '%s' not connected", subdomain)))
		return
	}
	
	// Crear request
	req := &Request{
		ID:       fmt.Sprintf("%d", time.Now().UnixNano()),
		HTTPReq:  r,
		Response: make(chan *Response, 1),
	}
	
	// Enviar al túnel
	select {
	case tunnel.Requests <- req:
		// Request encolado
	case <-time.After(5 * time.Second):
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Tunnel queue full"))
		return
	}
	
	// Esperar respuesta
	resp := <-req.Response
	
	// Enviar respuesta al cliente HTTP
	for k, values := range resp.Headers {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write([]byte(resp.Body))
}

func printUsage() {
	fmt.Println(`DNET Server - túnel HTTP estilo ngrok

Uso:
  dnet-server start [flags]

Flags:
  -tunnel-addr string   Dirección de escucha del túnel TLS (default ":9000")
  -public-addr string   Dirección de escucha pública HTTP (default ":8080")
  -cert string          Certificado TLS del túnel, modo manual/autofirmado (default "server.crt")
  -key string           Clave privada TLS del túnel, modo manual/autofirmado (default "server.key")
  -base-domain string   Dominio base para resolver subdomains por Host (default "localhost")
  -domain string        Dominio real del túnel; si se indica, se usa Let's Encrypt en vez de -cert/-key
  -email string         Email de contacto para Let's Encrypt (opcional)
  -acme-http-addr string  Dirección del listener HTTP-01 de Let's Encrypt (default ":80")
  -acme-cache-dir string  Directorio donde cachear los certificados de Let's Encrypt (default "autocert-cache")
  -no-tls                Desactiva TLS en el túnel (texto plano). No recomendado salvo detrás
                         de otro canal ya cifrado (VPN, red privada) (default false)`)
}

func runStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	tunnelAddr := fs.String("tunnel-addr", getEnv("TUNNEL_ADDR", TunnelPort), "Dirección de escucha del túnel TLS")
	publicAddr := fs.String("public-addr", getEnv("PUBLIC_ADDR", PublicPort), "Dirección de escucha pública HTTP")
	certFile := fs.String("cert", getEnv("TLS_CERT_FILE", "server.crt"), "Certificado TLS del túnel, modo manual/autofirmado")
	keyFile := fs.String("key", getEnv("TLS_KEY_FILE", "server.key"), "Clave privada TLS del túnel, modo manual/autofirmado")
	baseDomain := fs.String("base-domain", getEnv("BASE_DOMAIN", "localhost"), "Dominio base para resolver subdomains por Host")
	domain := fs.String("domain", getEnv("DOMAIN", ""), "Dominio real del túnel; si se indica, se usa Let's Encrypt en vez de -cert/-key")
	email := fs.String("email", getEnv("ACME_EMAIL", ""), "Email de contacto para Let's Encrypt (opcional)")
	acmeHTTPAddr := fs.String("acme-http-addr", getEnv("ACME_HTTP_ADDR", ":80"), "Dirección del listener HTTP-01 de Let's Encrypt")
	acmeCacheDir := fs.String("acme-cache-dir", getEnv("ACME_CACHE_DIR", "autocert-cache"), "Directorio donde cachear los certificados de Let's Encrypt")
	noTLS := fs.Bool("no-tls", getEnv("NO_TLS", "") == "true", "Desactiva TLS en el túnel (texto plano)")
	fs.Parse(args)

	var ln net.Listener
	var err error

	if *noTLS {
		log.Println("⚠ TLS desactivado (-no-tls): el túnel viaja en texto plano, incluyendo el token de autenticación. Usar solo detrás de un canal ya cifrado.")
		ln, err = net.Listen("tcp", *tunnelAddr)
		if err != nil {
			log.Fatalf("Error listening on tunnel port: %v", err)
		}
		log.Printf("Waiting for tunnel clients (sin TLS) on %s...", *tunnelAddr)
	} else {
		// Obtener el tls.Config del túnel: Let's Encrypt si se indicó -domain, certificado manual si no.
		var tlsConfig *tls.Config
		if *domain != "" {
			manager := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache(*acmeCacheDir),
				HostPolicy: autocert.HostWhitelist(*domain),
				Email:      *email,
			}
			go func() {
				log.Printf("Starting ACME HTTP-01 challenge listener on %s...", *acmeHTTPAddr)
				if err := http.ListenAndServe(*acmeHTTPAddr, manager.HTTPHandler(nil)); err != nil {
					log.Printf("ACME challenge server error: %v", err)
				}
			}()
			tlsConfig = manager.TLSConfig()
			log.Printf("Using Let's Encrypt certificate for %s (cache: %s)", *domain, *acmeCacheDir)
		} else {
			cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
			if err != nil {
				log.Fatalf("Error loading TLS cert/key (%s/%s): %v", *certFile, *keyFile, err)
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		}

		ln, err = tls.Listen("tcp", *tunnelAddr, tlsConfig)
		if err != nil {
			log.Fatalf("Error listening on tunnel port: %v", err)
		}
		log.Printf("Waiting for tunnel clients (TLS) on %s...", *tunnelAddr)
	}

	// Aceptar múltiples clientes
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("Error accepting connection: %v", err)
				continue
			}
			go handleTunnelConnection(conn)
		}
	}()

	// Servidor HTTP público
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handlePublic(w, r, *baseDomain)
	})
	log.Printf("Public HTTP server on %s (base domain: %s)...", *publicAddr, *baseDomain)
	log.Printf("Valid tokens: %v", getTokensList())
	log.Fatal(http.ListenAndServe(*publicAddr, nil))
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "start":
		runStart(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Comando desconocido: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func getTokensList() []string {
	tokens := make([]string, 0, len(validTokens))
	for token := range validTokens {
		tokens = append(tokens, token)
	}
	return tokens
}
