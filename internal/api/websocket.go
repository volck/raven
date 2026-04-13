package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		host := r.Host
		// Allow same-origin requests: origin must end with the host
		return strings.HasSuffix(origin, "://"+host)
	},
}

// WSMessage is the envelope sent over the WebSocket.
type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// Hub manages WebSocket clients and broadcasts messages.
type Hub struct {
	mu      sync.Mutex
	clients map[*wsClient]struct{}
}

type wsClient struct {
	conn *websocket.Conn
	send chan []byte
}

// NewHub creates a new Hub.
func NewHub() *Hub {
	return &Hub{
		clients: make(map[*wsClient]struct{}),
	}
}

// Broadcast sends a JSON message to all connected clients.
func (h *Hub) Broadcast(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.send <- data:
		default:
			// slow client, drop it
			close(c.send)
			delete(h.clients, c)
		}
	}
}

func (h *Hub) addClient(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = struct{}{}
}

func (h *Hub) removeClient(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; ok {
		close(c.send)
		delete(h.clients, c)
	}
}

// ClientCount returns the number of connected WebSocket clients.
func (h *Hub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// ServeWS handles WebSocket upgrade and runs the read/write pumps.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		jsonLogger.Error("websocket upgrade failed", "error", err)
		return
	}
	c := &wsClient{
		conn: conn,
		send: make(chan []byte, 64),
	}
	h.addClient(c)

	// Write pump
	go func() {
		defer func() {
			conn.Close()
			h.removeClient(c)
		}()
		for msg := range c.send {
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}()

	// Read pump — just consume (for pings/close)
	go func() {
		defer func() {
			h.removeClient(c)
			conn.Close()
		}()
		conn.SetReadLimit(512)
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			return nil
		})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()

	// Ping ticker to keep connection alive
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			h.mu.Lock()
			_, exists := h.clients[c]
			h.mu.Unlock()
			if !exists {
				return
			}
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}()
}
