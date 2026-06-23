package main

import (
	"bufio"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"
)

// Configuración básica
const (
	TunnelPort         = ":9000"            // Puerto para el túnel
	PublicPort         = ":8080"             // Puerto público para exponer
	DefaultMaxBodySize = 10 * 1024 * 1024 // 10 MB
)

// maxBodySize limita cuánto se lee del body de cada request pública antes de
// reenviarla por el túnel. Se fija una sola vez en runStart a partir del flag
// -max-body-size; el resto del código lo lee como variable de solo-lectura.
var maxBodySize int64 = DefaultMaxBodySize

// errBodyTooLarge señala que el body excede maxBodySize.
var errBodyTooLarge = errors.New("body exceeds max size")

// limitedRead lee como máximo maxBytes+1 bytes de r. Si el resultado supera
// maxBytes, devuelve errBodyTooLarge sin haber materializado un body más
// grande que el límite en memoria.
func limitedRead(r io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errBodyTooLarge
	}
	return data, nil
}

// getEnv devuelve el valor de la variable de entorno o, si no está definida, el default.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvInt64 devuelve el valor numérico de la variable de entorno, o el default
// si no está definida o no es un número válido.
func getEnvInt64(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

// getEnvFloat64 devuelve el valor numérico (float) de la variable de entorno,
// o el default si no está definida o no es un número válido.
func getEnvFloat64(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return n
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
	Type      string          `json:"type"` // "auth", "auth_ok", "auth_error", "request", "response"
	Token     string          `json:"token,omitempty"`
	Subdomain string          `json:"subdomain,omitempty"`
	ReqID     string          `json:"req_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

var (
	tunnels = make(map[string]*Tunnel) // subdomain -> tunnel
	mu      sync.RWMutex
)

// subdomainRe valida que un subdomain sea una etiqueta DNS razonable: minúsculas,
// dígitos y guiones, sin empezar ni terminar en guión. Se aplica tanto al
// subdomain pedido explícitamente como al default (= username), para que
// extractSubdomain nunca tenga que lidiar con algo inesperado más adelante.
var subdomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validSubdomain(s string) bool {
	return subdomainRe.MatchString(s)
}

// sendAuthMessage escribe un Message de autenticación (auth_ok o auth_error)
// al cliente. Para auth_error, reason va en Data como un string JSON, así el
// cliente puede mostrar el motivo real en vez de un "authentication failed" genérico.
func sendAuthMessage(conn net.Conn, msgType, reason string) {
	resp := Message{Type: msgType}
	if reason != "" {
		resp.Data, _ = json.Marshal(reason)
	}
	data, _ := json.Marshal(resp)
	conn.Write(append(data, '\n'))
}

// authenticateClient valida el token contra la base de datos y resuelve el
// subdomain pedido por el cliente (o el username si no pidió ninguno). No
// envía todavía auth_ok: eso queda para después de reservar el subdomain en
// handleTunnelConnection, porque recién ahí se sabe si hay conflicto con otro
// túnel activo. Tampoco envía auth_error en el caso de token inválido — ese
// camino históricamente no confirma nada al cliente (evita filtrar si un
// token existe o no); sí lo hace para el conflicto de subdomain, que no es
// information disclosure.
func authenticateClient(conn net.Conn, db *sql.DB) (user, subdomain string, err error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

	// Leer mensaje de autenticación
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return "", "", err
	}

	var msg Message
	if err := json.Unmarshal(line, &msg); err != nil {
		return "", "", err
	}

	if msg.Type != "auth" {
		return "", "", fmt.Errorf("expected auth message")
	}

	// Validar token contra la base de datos
	user, valid, err := lookupToken(db, msg.Token)
	if err != nil {
		return "", "", fmt.Errorf("token lookup failed: %w", err)
	}
	if !valid {
		return "", "", fmt.Errorf("invalid token")
	}

	subdomain = msg.Subdomain
	if subdomain == "" {
		subdomain = user
	}
	if !validSubdomain(subdomain) {
		return "", "", fmt.Errorf("invalid subdomain %q", subdomain)
	}

	conn.SetReadDeadline(time.Time{})
	return user, subdomain, nil
}

func handleTunnelConnection(conn net.Conn, db *sql.DB) {
	defer conn.Close()

	// Autenticar cliente y resolver el subdomain pedido
	user, subdomain, err := authenticateClient(conn, db)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return
	}

	// Crear túnel y reservar el subdomain atómicamente: si ya hay un túnel
	// activo con ese subdomain (de este mismo token u otro), se rechaza en vez
	// de pisarlo silenciosamente — eso es lo que permite que un solo token
	// sostenga varios túneles a la vez (cada uno con su propio -subdomain) sin
	// que uno eche al otro por accidente.
	tunnel := &Tunnel{
		Conn:            conn,
		User:            user,
		Subdomain:       subdomain,
		ConnectedAt:     time.Now(),
		Requests:        make(chan *Request, 100),
		pendingRequests: make(map[string]chan *Response),
		pendingMu:       &sync.Mutex{},
	}

	mu.Lock()
	if _, exists := tunnels[subdomain]; exists {
		mu.Unlock()
		log.Printf("Subdomain %q already in use, rejecting connection from user %s", subdomain, user)
		sendAuthMessage(conn, "auth_error", fmt.Sprintf("subdomain %q already in use", subdomain))
		return
	}
	tunnels[subdomain] = tunnel
	mu.Unlock()

	sendAuthMessage(conn, "auth_ok", "")
	log.Printf("Tunnel established for user: %s (subdomain: %s)", user, subdomain)

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

// handleTunnelRequest registra el request pendiente y lo envía al cliente por el
// túnel. No espera la respuesta: eso es responsabilidad exclusiva de handlePublic,
// que es quien tiene el channel req.Response en su goroutine (una por request HTTP
// entrante). Si ambas funciones recibieran del mismo channel (como antes), competirían
// por el único valor que llega — quien pierda la carrera se queda esperando hasta el
// timeout de 30s en cada request, y como este sender es la única goroutine que drena
// tunnel.Requests por túnel, eso serializaba TODO el túnel a ~1 request cada 30s bajo
// concurrencia real. No reintroducir un receive de req.Response aquí.
func handleTunnelRequest(tunnel *Tunnel, req *Request) {
	// Leer el body con límite ANTES de registrar el request pendiente: si excede
	// el límite, respondemos directo sin tocar pendingRequests (nada que limpiar).
	body, err := limitedRead(req.HTTPReq.Body, maxBodySize)
	req.HTTPReq.Body.Close()
	if err != nil {
		statusCode := http.StatusBadGateway
		msg := fmt.Sprintf("Error reading request body: %v", err)
		if errors.Is(err, errBodyTooLarge) {
			statusCode = http.StatusRequestEntityTooLarge
			msg = fmt.Sprintf("Request body exceeds max size of %d bytes", maxBodySize)
		}
		req.Response <- &Response{StatusCode: statusCode, Body: msg}
		return
	}

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
		"method":  req.HTTPReq.Method,
		"path":    req.HTTPReq.URL.Path,
		"query":   req.HTTPReq.URL.RawQuery,
		"headers": req.HTTPReq.Header,
		"body":    string(body),
	}

	msg.Data, _ = json.Marshal(reqData)

	tunnel.mu.Lock()
	data, _ := json.Marshal(msg)
	_, err = tunnel.Conn.Write(append(data, '\n'))
	tunnel.mu.Unlock()

	if err != nil {
		log.Printf("Error sending request to tunnel: %v", err)
		tunnel.pendingMu.Lock()
		delete(tunnel.pendingRequests, req.ID)
		tunnel.pendingMu.Unlock()
		req.Response <- &Response{
			StatusCode: 502,
			Body:       "Bad Gateway",
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

// clientIP devuelve la IP del que hace la request pública, sin el puerto.
// No considera X-Forwarded-For ni similares (serían spoofables sin un proxy
// de confianza configurado explícitamente) — usa la IP real de la conexión TCP.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// publicConfig agrupa la configuración de handlePublic que antes se pasaba
// como parámetros sueltos; crece con el tiempo (rate limiting agregó dos
// campos más), así que conviene mantenerlo así en vez de seguir agregando
// parámetros a la función.
type publicConfig struct {
	baseDomain        string
	ipLimiters        *limiterStore
	subdomainLimiters *limiterStore
}

func handlePublic(w http.ResponseWriter, r *http.Request, cfg publicConfig) {
	// Determinar subdomain a partir del Host real de la request
	subdomain, ok := extractSubdomain(r.Host, cfg.baseDomain)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Host inválido %q, se espera <subdomain>.%s", r.Host, cfg.baseDomain)))
		return
	}

	// Rate limiting: por IP del que llama y por subdomain del túnel. Cualquiera
	// de los dos que esté agotado bloquea la request — protege tanto contra un
	// solo cliente abusivo como contra que un túnel concreto sature al resto.
	ip := clientIP(r)
	if !cfg.ipLimiters.allow(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("Rate limit exceeded for your IP"))
		return
	}
	if !cfg.subdomainLimiters.allow(subdomain) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(fmt.Sprintf("Rate limit exceeded for tunnel '%s'", subdomain)))
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
	
	// Esperar respuesta (con timeout). Único receptor de req.Response — ver el
	// comentario en handleTunnelRequest sobre por qué no debe haber otro.
	var resp *Response
	select {
	case resp = <-req.Response:
	case <-time.After(30 * time.Second):
		tunnel.pendingMu.Lock()
		delete(tunnel.pendingRequests, req.ID)
		tunnel.pendingMu.Unlock()
		w.WriteHeader(http.StatusGatewayTimeout)
		w.Write([]byte("Gateway Timeout"))
		return
	}

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
                         de otro canal ya cifrado (VPN, red privada) (default false)
  -db-dsn string         Cadena de conexión a PostgreSQL para validar tokens (requerido)
                         ej: "postgres://usuario:clave@localhost:5432/dnet?sslmode=disable"
  -max-body-size int     Tamaño máximo (en bytes) del body de cada request pública
                         antes de reenviarla por el túnel (default 10485760, 10 MB)
  -rate-limit-ip float             Requests/segundo permitidas por IP (default 20)
  -rate-limit-ip-burst int          Ráfaga permitida por IP (default 40)
  -rate-limit-subdomain float       Requests/segundo permitidas por túnel/subdomain (default 50)
  -rate-limit-subdomain-burst int   Ráfaga permitida por túnel/subdomain (default 100)

Gestión de tokens (-db-dsn antes de los argumentos, o usar DATABASE_URL):
  dnet-server token add [-db-dsn ...] <token> <username>
  dnet-server token list [-db-dsn ...]
  dnet-server token remove [-db-dsn ...] <token>`)
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
	dbDSN := fs.String("db-dsn", getEnv("DATABASE_URL", ""), "Cadena de conexión a PostgreSQL para validar tokens")
	maxBody := fs.Int64("max-body-size", getEnvInt64("MAX_BODY_SIZE", DefaultMaxBodySize), "Tamaño máximo en bytes del body de cada request pública")
	rateLimitIP := fs.Float64("rate-limit-ip", getEnvFloat64("RATE_LIMIT_IP", 20), "Requests/segundo permitidas por IP")
	rateLimitIPBurst := fs.Int("rate-limit-ip-burst", int(getEnvInt64("RATE_LIMIT_IP_BURST", 40)), "Ráfaga permitida por IP")
	rateLimitSubdomain := fs.Float64("rate-limit-subdomain", getEnvFloat64("RATE_LIMIT_SUBDOMAIN", 50), "Requests/segundo permitidas por túnel/subdomain")
	rateLimitSubdomainBurst := fs.Int("rate-limit-subdomain-burst", int(getEnvInt64("RATE_LIMIT_SUBDOMAIN_BURST", 100)), "Ráfaga permitida por túnel/subdomain")
	fs.Parse(args)

	maxBodySize = *maxBody

	ipLimiters := newLimiterStore(rate.Limit(*rateLimitIP), *rateLimitIPBurst)
	subdomainLimiters := newLimiterStore(rate.Limit(*rateLimitSubdomain), *rateLimitSubdomainBurst)
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			ipLimiters.cleanup(30 * time.Minute)
			subdomainLimiters.cleanup(30 * time.Minute)
		}
	}()

	if *dbDSN == "" {
		log.Fatal("Falta -db-dsn (o DATABASE_URL): se requiere una base de datos PostgreSQL para validar tokens")
	}
	db, err := openTokenDB(*dbDSN)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	var ln net.Listener

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
			go handleTunnelConnection(conn, db)
		}
	}()

	// Servidor HTTP público
	publicCfg := publicConfig{
		baseDomain:        *baseDomain,
		ipLimiters:        ipLimiters,
		subdomainLimiters: subdomainLimiters,
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handlePublic(w, r, publicCfg)
	})
	log.Printf("Public HTTP server on %s (base domain: %s, rate limit: %.0f req/s/IP, %.0f req/s/subdomain)...",
		*publicAddr, *baseDomain, *rateLimitIP, *rateLimitSubdomain)
	if tokens, err := listTokens(db); err == nil {
		log.Printf("Tokens registrados: %d", len(tokens))
	}
	log.Fatal(http.ListenAndServe(*publicAddr, nil))
}

func runToken(args []string) {
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	sub := args[0]

	fs := flag.NewFlagSet("token "+sub, flag.ExitOnError)
	dbDSN := fs.String("db-dsn", getEnv("DATABASE_URL", ""), "Cadena de conexión a PostgreSQL")
	fs.Parse(args[1:])
	rest := fs.Args()

	if *dbDSN == "" {
		log.Fatal("Falta -db-dsn (o DATABASE_URL)")
	}
	db, err := openTokenDB(*dbDSN)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	switch sub {
	case "add":
		if len(rest) < 2 {
			log.Fatal("Uso: dnet-server token add <token> <username>")
		}
		if err := addToken(db, rest[0], rest[1]); err != nil {
			log.Fatalf("Error adding token: %v", err)
		}
		fmt.Printf("Token agregado: %s -> %s\n", rest[0], rest[1])
	case "remove":
		if len(rest) < 1 {
			log.Fatal("Uso: dnet-server token remove <token>")
		}
		found, err := removeToken(db, rest[0])
		if err != nil {
			log.Fatalf("Error removing token: %v", err)
		}
		if !found {
			fmt.Printf("Token no encontrado: %s\n", rest[0])
			os.Exit(1)
		}
		fmt.Printf("Token eliminado: %s\n", rest[0])
	case "list":
		tokens, err := listTokens(db)
		if err != nil {
			log.Fatalf("Error listing tokens: %v", err)
		}
		if len(tokens) == 0 {
			fmt.Println("No hay tokens registrados.")
			return
		}
		for _, t := range tokens {
			fmt.Printf("%s\t%s\n", t.Username, t.Token)
		}
	default:
		fmt.Fprintf(os.Stderr, "Subcomando desconocido: %s\n\n", sub)
		printUsage()
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "start":
		runStart(os.Args[2:])
	case "token":
		runToken(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Comando desconocido: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}
