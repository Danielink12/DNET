package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestExtractSubdomain(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		baseDomain string
		wantSub    string
		wantOK     bool
	}{
		{"valid subdomain", "demo.localhost", "localhost", "demo", true},
		{"valid subdomain with port", "demo.localhost:8080", "localhost", "demo", true},
		{"no subdomain", "localhost", "localhost", "", false},
		{"nested subdomain rejected", "a.b.localhost", "localhost", "", false},
		{"wrong base domain", "demo.example.com", "localhost", "", false},
		{"empty host", "", "localhost", "", false},
		{"real domain", "demo.tudominio.com", "tudominio.com", "demo", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sub, ok := extractSubdomain(c.host, c.baseDomain)
			if sub != c.wantSub || ok != c.wantOK {
				t.Errorf("extractSubdomain(%q, %q) = (%q, %v), want (%q, %v)",
					c.host, c.baseDomain, sub, ok, c.wantSub, c.wantOK)
			}
		})
	}
}

func TestLimitedRead(t *testing.T) {
	t.Run("under limit", func(t *testing.T) {
		data, err := limitedRead(strings.NewReader("hello"), 10)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "hello" {
			t.Errorf("got %q, want %q", data, "hello")
		}
	})

	t.Run("exactly at limit", func(t *testing.T) {
		data, err := limitedRead(strings.NewReader("hello"), 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "hello" {
			t.Errorf("got %q, want %q", data, "hello")
		}
	})

	t.Run("over limit", func(t *testing.T) {
		_, err := limitedRead(strings.NewReader("hello world"), 5)
		if !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("got error %v, want errBodyTooLarge", err)
		}
	})

	t.Run("empty reader", func(t *testing.T) {
		data, err := limitedRead(strings.NewReader(""), 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 0 {
			t.Errorf("got %q, want empty", data)
		}
	})
}

func TestGetEnv(t *testing.T) {
	t.Setenv("DNET_TEST_VAR", "")
	if got := getEnv("DNET_TEST_VAR", "fallback"); got != "fallback" {
		t.Errorf("got %q, want fallback when unset", got)
	}

	t.Setenv("DNET_TEST_VAR", "value")
	if got := getEnv("DNET_TEST_VAR", "fallback"); got != "value" {
		t.Errorf("got %q, want value", got)
	}
}

func TestGetEnvInt64(t *testing.T) {
	t.Setenv("DNET_TEST_INT", "")
	if got := getEnvInt64("DNET_TEST_INT", 42); got != 42 {
		t.Errorf("got %d, want 42 when unset", got)
	}

	t.Setenv("DNET_TEST_INT", "not-a-number")
	if got := getEnvInt64("DNET_TEST_INT", 42); got != 42 {
		t.Errorf("got %d, want fallback 42 for invalid value", got)
	}

	t.Setenv("DNET_TEST_INT", "12345")
	if got := getEnvInt64("DNET_TEST_INT", 42); got != 12345 {
		t.Errorf("got %d, want 12345", got)
	}
}

// testPublicConfig devuelve un publicConfig con límites de tasa altos para que
// los tests no se vean afectados por rate limiting (eso se prueba aparte).
func testPublicConfig(baseDomain string) publicConfig {
	return publicConfig{
		baseDomain:        baseDomain,
		ipLimiters:        newLimiterStore(1000, 1000),
		subdomainLimiters: newLimiterStore(1000, 1000),
	}
}

func TestHandlePublic_InvalidHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Host = "localhost" // sin subdomain
	w := httptest.NewRecorder()

	handlePublic(w, req, testPublicConfig("localhost"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandlePublic_TunnelNotConnected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Host = "noexiste.localhost"
	w := httptest.NewRecorder()

	handlePublic(w, req, testPublicConfig("localhost"))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestHandlePublic_Success(t *testing.T) {
	tunnel := &Tunnel{Requests: make(chan *Request, 1)}

	mu.Lock()
	tunnels["demo"] = tunnel
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		delete(tunnels, "demo")
		mu.Unlock()
	})

	// Simula al cliente del túnel: responde apenas recibe el request.
	go func() {
		req := <-tunnel.Requests
		req.Response <- &Response{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{"X-Test": {"yes"}},
			Body:       "hello from tunnel",
		}
	}()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/path", nil)
	req.Host = "demo.localhost"
	w := httptest.NewRecorder()

	handlePublic(w, req, testPublicConfig("localhost"))

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Body.String(); got != "hello from tunnel" {
		t.Errorf("got body %q, want %q", got, "hello from tunnel")
	}
	if got := w.Header().Get("X-Test"); got != "yes" {
		t.Errorf("got header X-Test=%q, want %q", got, "yes")
	}
}

func TestHandleTunnelRequest_BodyTooLarge(t *testing.T) {
	oldMax := maxBodySize
	maxBodySize = 5
	t.Cleanup(func() { maxBodySize = oldMax })

	httpReq := httptest.NewRequest(http.MethodPost, "http://localhost/", io.NopCloser(strings.NewReader("this body is way over the limit")))

	tunnel := &Tunnel{
		mu:              sync.Mutex{},
		pendingRequests: make(map[string]chan *Response),
		pendingMu:       &sync.Mutex{},
	}
	req := &Request{
		ID:       "test-1",
		HTTPReq:  httpReq,
		Response: make(chan *Response, 1),
	}

	handleTunnelRequest(tunnel, req)

	resp := <-req.Response
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}

	// No debe haber quedado nada registrado como pendiente.
	tunnel.pendingMu.Lock()
	defer tunnel.pendingMu.Unlock()
	if len(tunnel.pendingRequests) != 0 {
		t.Errorf("pendingRequests should be empty, got %d entries", len(tunnel.pendingRequests))
	}
}

func TestValidSubdomain(t *testing.T) {
	cases := []struct {
		name string
		sub  string
		want bool
	}{
		{"simple", "demo", true},
		{"with digits", "user1", true},
		{"with hyphen", "my-app", true},
		{"single char", "a", true},
		{"empty", "", false},
		{"uppercase rejected", "Demo", false},
		{"starts with hyphen", "-demo", false},
		{"ends with hyphen", "demo-", false},
		{"contains dot", "demo.sub", false},
		{"contains space", "demo app", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := validSubdomain(c.sub); got != c.want {
				t.Errorf("validSubdomain(%q) = %v, want %v", c.sub, got, c.want)
			}
		})
	}
}

// authOverPipe simula el lado del cliente del protocolo de auth sobre un
// net.Pipe, sin necesitar un client.go real: escribe el mensaje "auth" y
// devuelve la respuesta del servidor ya parseada.
func authOverPipe(t *testing.T, conn net.Conn, token, subdomain string) Message {
	t.Helper()

	msg := Message{Type: "auth", Token: token, Subdomain: subdomain}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("error marshaling auth message: %v", err)
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		t.Fatalf("error writing auth message: %v", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("error reading auth response: %v", err)
	}

	var resp Message
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("error parsing auth response: %v", err)
	}
	return resp
}

func TestHandleTunnelConnection_SubdomainConflict(t *testing.T) {
	db := openTestDB(t) // se salta si TEST_DATABASE_URL no está definida

	tokenA := fmt.Sprintf("test-token-a-%d", os.Getpid())
	tokenB := fmt.Sprintf("test-token-b-%d", os.Getpid())
	if err := addToken(db, tokenA, "usera"); err != nil {
		t.Fatalf("addToken: %v", err)
	}
	if err := addToken(db, tokenB, "userb"); err != nil {
		t.Fatalf("addToken: %v", err)
	}
	t.Cleanup(func() {
		removeToken(db, tokenA)
		removeToken(db, tokenB)
	})

	const subdomain = "shared-test-subdomain"
	t.Cleanup(func() {
		mu.Lock()
		delete(tunnels, subdomain)
		mu.Unlock()
	})

	// Primera conexión: pide el subdomain y debería obtenerlo.
	clientConn1, serverConn1 := net.Pipe()
	go handleTunnelConnection(serverConn1, db)
	t.Cleanup(func() { clientConn1.Close() })

	resp1 := authOverPipe(t, clientConn1, tokenA, subdomain)
	if resp1.Type != "auth_ok" {
		t.Fatalf("primera conexión: got type %q, want auth_ok", resp1.Type)
	}

	// Segunda conexión: mismo subdomain, otro token — debe rechazarse.
	clientConn2, serverConn2 := net.Pipe()
	go handleTunnelConnection(serverConn2, db)
	t.Cleanup(func() { clientConn2.Close() })

	resp2 := authOverPipe(t, clientConn2, tokenB, subdomain)
	if resp2.Type != "auth_error" {
		t.Fatalf("segunda conexión: got type %q, want auth_error", resp2.Type)
	}
	var reason string
	if err := json.Unmarshal(resp2.Data, &reason); err != nil {
		t.Fatalf("error parsing auth_error reason: %v", err)
	}
	if !strings.Contains(reason, "already in use") {
		t.Errorf("got reason %q, want it to mention the subdomain is already in use", reason)
	}
}
