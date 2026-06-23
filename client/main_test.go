package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

	t.Setenv("DNET_TEST_INT", "777")
	if got := getEnvInt64("DNET_TEST_INT", 42); got != 777 {
		t.Errorf("got %d, want 777", got)
	}
}

func TestLoadTLSConfig_SystemTrust(t *testing.T) {
	cfg := loadTLSConfig("", "example.com:9000", "")

	if cfg.RootCAs != nil {
		t.Error("RootCAs debería ser nil para confiar en el almacén del sistema")
	}
	if cfg.ServerName != "example.com" {
		t.Errorf("got ServerName %q, want example.com", cfg.ServerName)
	}
}

func TestLoadTLSConfig_ServerNameOverride(t *testing.T) {
	cfg := loadTLSConfig("", "1.2.3.4:9000", "tunnel.example.com")

	if cfg.ServerName != "tunnel.example.com" {
		t.Errorf("got ServerName %q, want tunnel.example.com (override)", cfg.ServerName)
	}
}

func TestLoadTLSConfig_CustomCA(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("error writing test cert: %v", err)
	}

	cfg := loadTLSConfig(caFile, "example.com:9000", "")

	if cfg.RootCAs == nil {
		t.Fatal("RootCAs no debería ser nil cuando se indica un archivo de CA")
	}
}

// generateTestCertPEM genera un certificado autofirmado mínimo en memoria,
// sin depender de openssl, solo para poblar un CertPool en los tests.
func generateTestCertPEM(t *testing.T) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("error creating certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestHandleRequest_Proxies(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("got method %s, want POST", r.Method)
		}
		if r.URL.Path != "/echo" {
			t.Errorf("got path %s, want /echo", r.URL.Path)
		}
		if r.URL.RawQuery != "x=1" {
			t.Errorf("got query %s, want x=1", r.URL.RawQuery)
		}
		if got := r.Header.Get("X-Custom"); got != "abc" {
			t.Errorf("got header X-Custom=%q, want abc", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "request body" {
			t.Errorf("got body %q, want %q", body, "request body")
		}

		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("response body"))
	}))
	defer backend.Close()

	reqData := HTTPRequest{
		Method:  http.MethodPost,
		Path:    "/echo",
		Query:   "x=1",
		Headers: map[string][]string{"X-Custom": {"abc"}},
		Body:    "request body",
	}

	resp, err := handleRequest(reqData, backend.URL, DefaultMaxBodySize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if resp.Body != "response body" {
		t.Errorf("got body %q, want %q", resp.Body, "response body")
	}
	cookies := resp.Headers["Set-Cookie"]
	if len(cookies) != 2 || cookies[0] != "a=1" || cookies[1] != "b=2" {
		t.Errorf("got Set-Cookie %v, want [a=1 b=2] (headers multivalor)", cookies)
	}
}

func TestHandleRequest_BodyTooLarge(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this response body is larger than the tiny test limit"))
	}))
	defer backend.Close()

	reqData := HTTPRequest{Method: http.MethodGet, Path: "/"}

	resp, err := handleRequest(reqData, backend.URL, 5)
	if err != nil {
		t.Fatalf("unexpected error (should be a normal 502 response, not a Go error): %v", err)
	}

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestHandleRequest_BackendUnreachable(t *testing.T) {
	reqData := HTTPRequest{Method: http.MethodGet, Path: "/"}

	_, err := handleRequest(reqData, "http://127.0.0.1:1", DefaultMaxBodySize)
	if err == nil {
		t.Fatal("esperaba un error al conectar a un puerto sin servicio")
	}
}
