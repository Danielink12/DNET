package main

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
)

// openTestDB conecta a la base indicada en TEST_DATABASE_URL. Si la variable no
// está definida, salta el test: estos son tests de integración contra un
// Postgres real (no hay forma liviana de mockear database/sql aquí), y no
// deben fallar la suite en máquinas sin Postgres disponible.
//
// Para correrlos:
//
//	docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16
//	TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable" go test ./...
func openTestDB(t *testing.T) *sql.DB {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL no está definida, se omiten los tests de integración con Postgres")
	}

	db, err := openTokenDB(dsn)
	if err != nil {
		t.Fatalf("error connecting to test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	return db
}

func TestTokenLifecycle(t *testing.T) {
	db := openTestDB(t)

	token := fmt.Sprintf("test-token-%d", os.Getpid())
	t.Cleanup(func() { removeToken(db, token) })

	// Token no existe todavía.
	_, ok, err := lookupToken(db, token)
	if err != nil {
		t.Fatalf("lookupToken error: %v", err)
	}
	if ok {
		t.Fatalf("token %q ya existía antes de agregarlo", token)
	}

	// Agregar y verificar.
	if err := addToken(db, token, "testuser"); err != nil {
		t.Fatalf("addToken error: %v", err)
	}
	username, ok, err := lookupToken(db, token)
	if err != nil {
		t.Fatalf("lookupToken error: %v", err)
	}
	if !ok || username != "testuser" {
		t.Fatalf("got (username=%q, ok=%v), want (testuser, true)", username, ok)
	}

	// Upsert: re-agregar con otro username actualiza, no falla.
	if err := addToken(db, token, "otheruser"); err != nil {
		t.Fatalf("addToken (upsert) error: %v", err)
	}
	username, _, err = lookupToken(db, token)
	if err != nil {
		t.Fatalf("lookupToken error: %v", err)
	}
	if username != "otheruser" {
		t.Fatalf("got username %q after upsert, want otheruser", username)
	}

	// Aparece en listTokens.
	tokens, err := listTokens(db)
	if err != nil {
		t.Fatalf("listTokens error: %v", err)
	}
	found := false
	for _, tok := range tokens {
		if tok.Token == token && tok.Username == "otheruser" {
			found = true
		}
	}
	if !found {
		t.Fatalf("token %q no aparece en listTokens", token)
	}

	// Eliminar y verificar que ya no exista.
	removed, err := removeToken(db, token)
	if err != nil {
		t.Fatalf("removeToken error: %v", err)
	}
	if !removed {
		t.Fatalf("removeToken devolvió found=false para un token existente")
	}
	_, ok, err = lookupToken(db, token)
	if err != nil {
		t.Fatalf("lookupToken error: %v", err)
	}
	if ok {
		t.Fatalf("el token %q sigue existiendo después de removeToken", token)
	}

	// Eliminar de nuevo: found=false, sin error.
	removed, err = removeToken(db, token)
	if err != nil {
		t.Fatalf("removeToken (segunda vez) error: %v", err)
	}
	if removed {
		t.Fatalf("removeToken devolvió found=true para un token ya eliminado")
	}
}
