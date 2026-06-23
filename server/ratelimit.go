package main

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiterStore mantiene un rate.Limiter por clave (IP o subdomain, según el
// store), creado de forma perezosa la primera vez que se ve esa clave.
// cleanup() debe llamarse periódicamente para no acumular entradas de claves
// que ya no generan tráfico (ver runStart).
type limiterStore struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
	rateLim rate.Limit
	burst   int
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newLimiterStore(r rate.Limit, burst int) *limiterStore {
	return &limiterStore{
		entries: make(map[string]*limiterEntry),
		rateLim: r,
		burst:   burst,
	}
}

// allow devuelve true si la clave todavía tiene cupo bajo su límite de tasa.
func (s *limiterStore) allow(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		entry = &limiterEntry{limiter: rate.NewLimiter(s.rateLim, s.burst)}
		s.entries[key] = entry
	}
	entry.lastSeen = time.Now()

	return entry.limiter.Allow()
}

// cleanup elimina las entradas sin tráfico en los últimos maxAge, para que el
// mapa no crezca sin límite con cada IP/subdomain nuevo que pasó por el túnel.
func (s *limiterStore) cleanup(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, entry := range s.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(s.entries, key)
		}
	}
}
