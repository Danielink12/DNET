# DNET - Túnel HTTP estilo ngrok

Implementación funcional de un túnel HTTP similar a ngrok en Go.

## Características Implementadas

### ✅ Autenticación con Tokens
- Sistema de tokens para identificar usuarios
- Validación en el servidor antes de establecer túnel

### ✅ Reconexión Automática
- El cliente reconecta automáticamente si pierde conexión
- Backoff exponencial para reintentos (2s → 4s → 8s → 30s max)

### ✅ Multiplexación
- Manejo de múltiples requests HTTP simultáneas sobre un solo túnel TCP
- Sistema de request/response con IDs únicos
- Procesamiento asíncrono de requests

### ✅ Múltiples Clientes
- El servidor puede manejar múltiples túneles simultáneamente
- Cada usuario/token tiene su propio subdomain por defecto, pero un mismo
  token puede sostener varios túneles a la vez pidiendo `-subdomain`
  explícitamente en cada uno
- Pedir un subdomain ya ocupado se rechaza explícitamente (no pisa al túnel existente)

### ✅ Protocolo JSON
- Mensajes estructurados en JSON sobre TCP
- Tipos: `auth`, `request`, `response`

## 📋 Comparación con ngrok

| Característica | ngrok | DNET |
|----------------|-------|------|
| Autenticación | ✅ | ✅ |
| Reconexión | ✅ | ✅ |
| Múltiples túneles | ✅ | ✅ |
| Multiplexación | ✅ | ✅ |
| HTTPS/TLS (túnel, vía Let's Encrypt) | ✅ | ✅ |
| Desactivar TLS (`-no-tls`, no recomendado) | ❌ | ✅ |
| HTTPS/TLS (puerto público) | ✅ | ❌ |
| Panel web | ✅ | ❌ |
| URLs personalizadas (subdomain por Host) | ✅ | ✅ |
| Compresión | ✅ | ❌ |
| Rate limiting | ✅ | ✅ |
| WebSockets | ✅ | ❌ |

## Instalación

```bash
# Compilar servidor
cd server
go build -o dnet-server main.go

# Compilar cliente
cd ../client
go build -o dnet-client main.go
```

## Uso Rápido

### 1. Iniciar el servidor

```bash
cd server
go run main.go start
```

El servidor escuchará en:
- Puerto 9000: Conexiones de túnel (cliente)
- Puerto 8080: HTTP público

Salida:
```
Waiting for tunnel clients on :9000...
Public HTTP server on :8080...
Valid tokens: [token_user1 token_user2 demo_token]
```

### 2. Iniciar servicio local

Ejemplo con Python:
```bash
# En otro terminal
python -m http.server 8081
```

### 3. Iniciar el cliente

El túnel usa TLS. Si el servidor corre con `-domain` (Let's Encrypt, recomendado en un VPS con dominio real), el cliente no necesita nada extra. Si corre con el certificado autofirmado por defecto (sin `-domain`, como en este ejemplo local), hay que indicarle la CA — ver `TESTING.md`:

```bash
cd client
go run main.go connect -ca ca.crt
```

El cliente:
- Se conecta al servidor (localhost:9000)
- Se autentica con el token configurado
- Expone tu servicio local (localhost:8081)

Salida:
```
DNET Client - Exposing http://localhost:8081
Using token: demo_token
✓ Connected to tunnel server!
✓ Authenticated successfully!
✓ Tunnel active! Listening for requests...
```

### 4. Probar el túnel

El subdomain se resuelve por el `Host` real de la request (`<subdomain>.<base-domain>`, `base-domain` default `localhost`):

```bash
# En otro terminal
curl -H "Host: demo.localhost" http://localhost:8080/
```

## Configuración de Tokens

Los tokens se gestionan en PostgreSQL, no en el código (ver `TESTING.md` para el detalle completo):

```bash
export DATABASE_URL="postgres://usuario:clave@localhost:5432/dnet?sslmode=disable"

./dnet-server token add demo_token demo
./dnet-server token list
./dnet-server token remove demo_token
```

### Cliente (`client/main.go`)

```go
const (
	ServerAddr = "localhost:9000"
	LocalAddr  = "http://localhost:8081"
	AuthToken  = "demo_token"  // ← Cambiar según tu token
)
```

## Protocolo de Mensajes

### Autenticación
```json
Cliente → Servidor:
{"type":"auth","token":"demo_token"}

Servidor → Cliente:
{"type":"auth_ok"}
```

### Request HTTP
```json
Servidor → Cliente:
{
  "type":"request",
  "req_id":"1234567890",
  "data": {
    "method":"GET",
    "path":"/",
    "query":"",
    "headers":{"User-Agent":["curl/7.68.0"]},
    "body":""
  }
}
```

### Response HTTP
```json
Cliente → Servidor:
{
  "type":"response",
  "req_id":"1234567890",
  "data": {
    "status_code":200,
    "headers":{"Content-Type":"text/html"},
    "body":"<html>...</html>"
  }
}
```

## Flujo de Trabajo

```
1. Cliente conecta → Servidor (puerto 9000)
2. Cliente envía token
3. Servidor valida y confirma
4. Usuario hace request → Servidor HTTP (puerto 8080)
5. Servidor identifica túnel por subdomain
6. Servidor envía request al Cliente via túnel
7. Cliente ejecuta request al servicio local
8. Cliente envía response al Servidor via túnel
9. Servidor envía response al Usuario
```

## Ejemplos de Uso

### Exponer servidor web local
```bash
# Terminal 1: Servidor DNET
cd server && go run main.go

# Terminal 2: Tu app web
cd my-web-app && npm run dev # localhost:8081

# Terminal 3: Cliente DNET
cd client && go run main.go

# Terminal 4: Probar
curl http://localhost:8080/?subdomain=demo
```

### Múltiples clientes

```bash
# Cliente 1 (usa token_user1)
# En client/main.go cambiar AuthToken = "token_user1"
go run main.go

# Cliente 2 (usa token_user2)
# En otro directorio, cambiar AuthToken = "token_user2"
go run main.go

# Acceder a cada uno
curl http://localhost:8080/?subdomain=user1
curl http://localhost:8080/?subdomain=user2
```

## Troubleshooting

### Error: "Tunnel not connected"
- Verificar que el cliente esté ejecutándose
- Verificar que el subdomain sea correcto

### Error: "invalid token"
- Verificar que el token del cliente esté en `validTokens` del servidor
- Verificar que no haya espacios extras en el token

### Error: "connection refused" al conectar al servidor
- Verificar que el servidor esté ejecutándose
- Verificar el puerto (default: 9000)

### Error: "Bad Gateway" en respuestas
- Verificar que el servicio local esté ejecutándose
- Verificar la URL en `LocalAddr` del cliente

## Mejoras Futuras (no implementadas)

- [x] HTTPS/TLS (túnel, vía Let's Encrypt o certificado manual)
- [ ] Panel web de inspección
- [ ] WebSockets
- [ ] Compresión
- [x] Base de datos para tokens (PostgreSQL)
- [ ] Logs persistentes
- [ ] Métricas y estadísticas
- [x] Rate limiting (por IP y por subdomain)
- [x] Custom domains (subdomain por Host)
- [x] Límite de tamaño de body

## Notas Técnicas

- **Protocolo**: JSON sobre TCP con delimitador `\n`
- **Timeouts**: 
  - Autenticación: 10s
  - Request: 30s
  - Gateway: 5s (cola)
- **Buffer**: 100 requests en cola por túnel
- **Reconexión**: Backoff exponencial 2s → 30s max

## Licencia

Proyecto educativo - Uso libre
