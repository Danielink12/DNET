package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestLimiterStore_AllowAndBurst(t *testing.T) {
	// rate.Limit(0) = nunca rellena el bucket; burst 2 = exactamente 2 lugares.
	store := newLimiterStore(rate.Limit(0), 2)

	if !store.allow("k") {
		t.Fatal("primera request debería permitirse (dentro del burst)")
	}
	if !store.allow("k") {
		t.Fatal("segunda request debería permitirse (dentro del burst)")
	}
	if store.allow("k") {
		t.Fatal("tercera request debería rechazarse (burst agotado)")
	}
}

func TestLimiterStore_PerKeyIsolation(t *testing.T) {
	store := newLimiterStore(rate.Limit(0), 1)

	if !store.allow("a") {
		t.Fatal("primera request de la clave 'a' debería permitirse")
	}
	if store.allow("a") {
		t.Fatal("segunda request de 'a' debería rechazarse")
	}
	// Clave distinta: su propio bucket, no comparte cupo con 'a'.
	if !store.allow("b") {
		t.Fatal("primera request de la clave 'b' debería permitirse (bucket independiente)")
	}
}

func TestLimiterStore_Cleanup(t *testing.T) {
	store := newLimiterStore(rate.Limit(0), 1)
	store.allow("stale")

	store.mu.Lock()
	store.entries["stale"].lastSeen = time.Now().Add(-time.Hour)
	store.mu.Unlock()

	store.cleanup(time.Minute)

	store.mu.Lock()
	_, exists := store.entries["stale"]
	store.mu.Unlock()
	if exists {
		t.Fatal("la entrada vieja debería haberse eliminado por cleanup")
	}
}

func TestHandlePublic_RateLimitedByIP(t *testing.T) {
	tunnel := &Tunnel{Requests: make(chan *Request, 10)}
	mu.Lock()
	tunnels["demo"] = tunnel
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		delete(tunnels, "demo")
		mu.Unlock()
	})

	// Responder a cualquier request que llegue, indefinidamente.
	go func() {
		for req := range tunnel.Requests {
			req.Response <- &Response{StatusCode: http.StatusOK, Body: "ok"}
		}
	}()

	cfg := publicConfig{
		baseDomain:        "localhost",
		ipLimiters:        newLimiterStore(rate.Limit(0), 1), // 1 sola request por IP, nunca se rellena
		subdomainLimiters: newLimiterStore(1000, 1000),       // sin restricción real
	}

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		r.Host = "demo.localhost"
		r.RemoteAddr = "203.0.113.1:5555"
		return r
	}

	w1 := httptest.NewRecorder()
	handlePublic(w1, newReq(), cfg)
	if w1.Code != http.StatusOK {
		t.Fatalf("primera request: got status %d, want %d", w1.Code, http.StatusOK)
	}

	w2 := httptest.NewRecorder()
	handlePublic(w2, newReq(), cfg)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("segunda request (misma IP): got status %d, want %d", w2.Code, http.StatusTooManyRequests)
	}
}

func TestHandlePublic_RateLimitedBySubdomain(t *testing.T) {
	tunnel := &Tunnel{Requests: make(chan *Request, 10)}
	mu.Lock()
	tunnels["demo"] = tunnel
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		delete(tunnels, "demo")
		mu.Unlock()
	})

	go func() {
		for req := range tunnel.Requests {
			req.Response <- &Response{StatusCode: http.StatusOK, Body: "ok"}
		}
	}()

	cfg := publicConfig{
		baseDomain:        "localhost",
		ipLimiters:        newLimiterStore(1000, 1000), // sin restricción real
		subdomainLimiters: newLimiterStore(rate.Limit(0), 1),
	}

	// Dos IPs distintas pegándole al mismo subdomain: el límite por subdomain
	// debe aplicar igual, sin que el límite por IP (alto) lo enmascare.
	r1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	r1.Host = "demo.localhost"
	r1.RemoteAddr = "203.0.113.1:5555"

	r2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	r2.Host = "demo.localhost"
	r2.RemoteAddr = "203.0.113.2:6666"

	w1 := httptest.NewRecorder()
	handlePublic(w1, r1, cfg)
	if w1.Code != http.StatusOK {
		t.Fatalf("primera request: got status %d, want %d", w1.Code, http.StatusOK)
	}

	w2 := httptest.NewRecorder()
	handlePublic(w2, r2, cfg)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("segunda request (mismo subdomain, otra IP): got status %d, want %d", w2.Code, http.StatusTooManyRequests)
	}
}
