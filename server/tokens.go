package main

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// openTokenDB conecta a Postgres y asegura que exista el esquema de tokens.
func openTokenDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			token      TEXT PRIMARY KEY,
			username   TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating tokens table: %w", err)
	}

	return db, nil
}

// lookupToken devuelve el username asociado al token, o ok=false si no existe.
func lookupToken(db *sql.DB, token string) (username string, ok bool, err error) {
	err = db.QueryRow(`SELECT username FROM tokens WHERE token = $1`, token).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return username, true, nil
}

// addToken inserta o actualiza un token. Devuelve error si ya existe con otro username.
func addToken(db *sql.DB, token, username string) error {
	_, err := db.Exec(`
		INSERT INTO tokens (token, username) VALUES ($1, $2)
		ON CONFLICT (token) DO UPDATE SET username = EXCLUDED.username
	`, token, username)
	return err
}

// removeToken elimina un token. Devuelve found=false si no existía.
func removeToken(db *sql.DB, token string) (found bool, err error) {
	res, err := db.Exec(`DELETE FROM tokens WHERE token = $1`, token)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

type tokenRow struct {
	Token    string
	Username string
}

// listTokens devuelve todos los tokens registrados, ordenados por username.
func listTokens(db *sql.DB) ([]tokenRow, error) {
	rows, err := db.Query(`SELECT token, username FROM tokens ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []tokenRow
	for rows.Next() {
		var t tokenRow
		if err := rows.Scan(&t.Token, &t.Username); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
