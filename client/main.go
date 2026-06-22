package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// Configuración básica
const (
	ServerAddr = "localhost:9000" // Dirección del servidor central
	LocalAddr  = "http://localhost:8081"   // Servicio local a exponer
	AuthToken  = "demo_token"      // Token de autenticación
)

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

func connectWithRetry() net.Conn {
	retryDelay := 2 * time.Second
	maxRetries := 5
	
	for attempt := 1; ; attempt++ {
		conn, err := net.Dial("tcp", ServerAddr)
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

func authenticate(conn net.Conn) error {
	// Enviar mensaje de autenticación
	authMsg := Message{
		Type:  "auth",
		Token: AuthToken,
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

func handleRequest(reqData HTTPRequest) (*HTTPResponse, error) {
	// Construir URL completa
	url := LocalAddr + reqData.Path
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

func listenForRequests(conn net.Conn) {
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
			go handleIncomingRequest(conn, msg)
		}
	}
}

func handleIncomingRequest(conn net.Conn, msg Message) {
	// Parsear request
	var reqData HTTPRequest
	if err := json.Unmarshal(msg.Data, &reqData); err != nil {
		log.Printf("Error parsing request data: %v", err)
		return
	}
	
	log.Printf("→ %s %s", reqData.Method, reqData.Path)
	
	// Ejecutar request local
	resp, err := handleRequest(reqData)
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

func main() {
	log.Printf("DNET Client - Exposing %s", LocalAddr)
	log.Printf("Using token: %s", AuthToken)
	
	for {
		// Conectar con reconexión automática
		conn := connectWithRetry()
		
		// Autenticar
		if err := authenticate(conn); err != nil {
			log.Printf("Authentication error: %v", err)
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		
		log.Println("✓ Tunnel active! Listening for requests...")
		
		// Escuchar requests
		listenForRequests(conn)
		
		// Si llegamos aquí, la conexión se cerró
		conn.Close()
		log.Println("Reconnecting in 3 seconds...")
		time.Sleep(3 * time.Second)
	}
}
