package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Configuración básica
const (
	ServerAddr = "localhost:9000" // Dirección del servidor central
	LocalAddr  = "http://localhost:8081"   // Servicio local a exponer
	AuthToken  = "demo_token"      // Token de autenticación
)

// getEnv devuelve el valor de la variable de entorno o, si no está definida, el default.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadTLSConfig construye el tls.Config para verificar el certificado del servidor.
// Si caFile está vacío, se confía en el almacén de certificados raíz del sistema
// (uso normal cuando el servidor tiene un certificado público real, ej. Let's Encrypt).
// Si caFile se indica, se usa esa CA en su lugar (certificados autofirmados/de prueba).
// Si serverNameOverride está vacío, el nombre esperado se deriva del host de serverAddr.
func loadTLSConfig(caFile, serverAddr, serverNameOverride string) *tls.Config {
	serverName := serverNameOverride
	if serverName == "" {
		serverName = strings.Split(serverAddr, ":")[0]
	}

	if caFile == "" {
		return &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("Error reading CA cert (%s): %v", caFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		log.Fatalf("Error parsing CA cert (%s)", caFile)
	}

	return &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
}

// Protocolo de mensajes
type Message struct {
	Type    string          `json:"type"` // "auth", "request", "response"
	Token   string          `json:"token,omitempty"`
	ReqID   string          `json:"req_id,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type HTTPRequest struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

type HTTPResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
}

// connectWithRetry conecta al servidor con reconexión y backoff exponencial.
// Si tlsConfig es nil, conecta en texto plano (modo -no-tls); si no, usa TLS.
func connectWithRetry(serverAddr string, tlsConfig *tls.Config) net.Conn {
	retryDelay := 2 * time.Second
	maxRetries := 5

	for attempt := 1; ; attempt++ {
		var conn net.Conn
		var err error
		if tlsConfig != nil {
			conn, err = tls.Dial("tcp", serverAddr, tlsConfig)
		} else {
			conn, err = net.Dial("tcp", serverAddr)
		}
		if err == nil {
			log.Println("✓ Connected to tunnel server!")
			return conn
		}
		
		log.Printf("✗ Connection failed (attempt %d): %v", attempt, err)
		
		if attempt >= maxRetries {
			log.Printf("Waiting %v before retry...", retryDelay)
			retryDelay *= 2
			if retryDelay > 30*time.Second {
				retryDelay = 30 * time.Second
			}
		}
		
		time.Sleep(retryDelay)
	}
}

func authenticate(conn net.Conn, token string) error {
	// Enviar mensaje de autenticación
	authMsg := Message{
		Type:  "auth",
		Token: token,
	}
	
	data, err := json.Marshal(authMsg)
	if err != nil {
		return err
	}
	
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return err
	}
	
	// Esperar confirmación
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})
	
	var response Message
	if err := json.Unmarshal(line, &response); err != nil {
		return err
	}
	
	if response.Type != "auth_ok" {
		return fmt.Errorf("authentication failed")
	}
	
	log.Println("✓ Authenticated successfully!")
	return nil
}

func handleRequest(reqData HTTPRequest, localAddr string) (*HTTPResponse, error) {
	// Construir URL completa
	url := localAddr + reqData.Path
	if reqData.Query != "" {
		url += "?" + reqData.Query
	}
	
	// Crear request HTTP
	req, err := http.NewRequest(reqData.Method, url, bytes.NewBufferString(reqData.Body))
	if err != nil {
		return nil, err
	}
	
	// Copiar headers
	for k, values := range reqData.Headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	
	// Ejecutar request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	// Leer respuesta
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	// Construir respuesta
	headers := map[string][]string(resp.Header)
	
	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(body),
	}, nil
}

func listenForRequests(conn net.Conn, localAddr string) {
	reader := bufio.NewReader(conn)

	for {
		// Leer mensaje
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				log.Println("Connection closed by server")
			} else {
				log.Printf("Error reading: %v", err)
			}
			return
		}

		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			log.Printf("Error parsing message: %v", err)
			continue
		}

		if msg.Type == "request" {
			go handleIncomingRequest(conn, msg, localAddr)
		}
	}
}

func handleIncomingRequest(conn net.Conn, msg Message, localAddr string) {
	// Parsear request
	var reqData HTTPRequest
	if err := json.Unmarshal(msg.Data, &reqData); err != nil {
		log.Printf("Error parsing request data: %v", err)
		return
	}

	log.Printf("→ %s %s", reqData.Method, reqData.Path)

	// Ejecutar request local
	resp, err := handleRequest(reqData, localAddr)
	if err != nil {
		log.Printf("Error handling request: %v", err)
		// Enviar error
		resp = &HTTPResponse{
			StatusCode: 502,
			Body:       fmt.Sprintf("Bad Gateway: %v", err),
		}
	}
	
	log.Printf("← %d %s", resp.StatusCode, reqData.Path)
	
	// Enviar respuesta
	responseMsg := Message{
		Type:  "response",
		ReqID: msg.ReqID,
	}
	responseMsg.Data, _ = json.Marshal(resp)
	
	data, _ := json.Marshal(responseMsg)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		log.Printf("Error sending response: %v", err)
	}
}

func printUsage() {
	fmt.Println(`DNET Client - expone un servicio local a través del túnel

Uso:
  dnet-client connect [flags]

Flags:
  -server string       Dirección del servidor DNET (default "localhost:9000")
  -local string        Servicio local a exponer (default "http://localhost:8081")
  -token string        Token de autenticación (default "demo_token")
  -ca string           Certificado CA para verificar al servidor. Vacío = confiar en el almacén
                       de certificados del sistema (uso normal con Let's Encrypt). Indicar un
                       archivo solo para certificados autofirmados/de prueba (default "")
  -server-name string  Nombre esperado en el certificado del servidor (default: host de -server)
  -no-tls              Conecta en texto plano, sin TLS (debe coincidir con el servidor). No
                       recomendado salvo detrás de otro canal ya cifrado (default false)`)
}

func runConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	serverAddr := fs.String("server", getEnv("SERVER_ADDR", ServerAddr), "Dirección del servidor DNET")
	localAddr := fs.String("local", getEnv("LOCAL_ADDR", LocalAddr), "Servicio local a exponer")
	authToken := fs.String("token", getEnv("AUTH_TOKEN", AuthToken), "Token de autenticación")
	caFile := fs.String("ca", getEnv("TLS_CA_FILE", ""), "Certificado CA para verificar al servidor (vacío = almacén del sistema)")
	serverName := fs.String("server-name", getEnv("TLS_SERVER_NAME", ""), "Nombre esperado en el certificado del servidor")
	noTLS := fs.Bool("no-tls", getEnv("NO_TLS", "") == "true", "Conecta en texto plano, sin TLS")
	fs.Parse(args)

	var tlsConfig *tls.Config
	if *noTLS {
		log.Println("⚠ TLS desactivado (-no-tls): la conexión y el token viajan en texto plano. Usar solo detrás de un canal ya cifrado.")
	} else {
		tlsConfig = loadTLSConfig(*caFile, *serverAddr, *serverName)
	}

	log.Printf("DNET Client - Exposing %s", *localAddr)
	if *noTLS {
		log.Printf("Connecting to %s (sin TLS)", *serverAddr)
	} else {
		log.Printf("Connecting to %s (TLS)", *serverAddr)
	}
	log.Printf("Using token: %s", *authToken)

	for {
		// Conectar con reconexión automática
		conn := connectWithRetry(*serverAddr, tlsConfig)

		// Autenticar
		if err := authenticate(conn, *authToken); err != nil {
			log.Printf("Authentication error: %v", err)
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		log.Println("✓ Tunnel active! Listening for requests...")

		// Escuchar requests
		listenForRequests(conn, *localAddr)

		// Si llegamos aquí, la conexión se cerró
		conn.Close()
		log.Println("Reconnecting in 3 seconds...")
		time.Sleep(3 * time.Second)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "connect":
		runConnect(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Comando desconocido: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}
