package flock

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	rvclient "github.com/volck/raven/internal/flock/raven"
)

// FleetMessage is what flock fans out to its WS subscribers — a raven
// WSMessage tagged with the source target and (best-effort) engine.
type FleetMessage struct {
	Target    string          `json:"target"`
	Engine    string          `json:"engine,omitempty"`
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	ObserveAt time.Time       `json:"observed_at"`
}

// WSHub is flock's local WebSocket hub. Subscribers receive every inbound
// raven message tagged with its target.
type WSHub struct {
	logger *slog.Logger

	mu      sync.Mutex
	clients map[*wsClient]struct{}

	upgrader websocket.Upgrader
}

type wsClient struct {
	conn *websocket.Conn
	send chan []byte
}

// NewWSHub constructs a hub. The CheckOrigin policy mirrors raven's:
// same-origin only by default.
func NewWSHub(logger *slog.Logger) *WSHub {
	return &WSHub{
		logger:  logger,
		clients: map[*wsClient]struct{}{},
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// Broadcast marshals msg and pushes it to every connected client. Slow
// clients are dropped — broadcasting must never block the bridge.
func (h *WSHub) Broadcast(msg FleetMessage) {
	if msg.ObserveAt.IsZero() {
		msg.ObserveAt = time.Now()
	}
	buf, err := json.Marshal(msg)
	if err != nil {
		h.logger.Warn("ws.broadcast.encode_failed", "err", err.Error())
		return
	}
	h.mu.Lock()
	for c := range h.clients {
		select {
		case c.send <- buf:
		default:
			// Drop slow client.
			close(c.send)
			delete(h.clients, c)
		}
	}
	h.mu.Unlock()
}

// ClientCount returns the number of currently connected subscribers.
func (h *WSHub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// ServeHTTP upgrades the HTTP connection to a WebSocket and starts the
// read+write pumps.
func (h *WSHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Warn("ws.upgrade_failed", "err", err.Error())
		return
	}
	c := &wsClient{conn: conn, send: make(chan []byte, 256)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()

	go h.writePump(c)
	go h.readPump(c)
}

func (h *WSHub) writePump(c *wsClient) {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (h *WSHub) readPump(c *wsClient) {
	defer func() {
		h.mu.Lock()
		if _, ok := h.clients[c]; ok {
			delete(h.clients, c)
			close(c.send)
		}
		h.mu.Unlock()
		_ = c.conn.Close()
	}()
	c.conn.SetReadLimit(512)
	_ = c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

// WSSubscriber is the minimal interface the WSBridge needs to talk to a
// raven /ws endpoint. rvclient.Client satisfies this.
type WSSubscriber interface {
	Subscribe(ctx context.Context, baseURL string, out chan<- rvclient.WSMessage) error
}

// WSBridge keeps one long-lived subscription per raven target, reconciling
// with Snapshot changes. Inbound messages are tagged and pushed to a Hub.
type WSBridge struct {
	logger *slog.Logger
	sub    WSSubscriber
	hub    *WSHub

	backoffMin time.Duration
	backoffMax time.Duration

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

// NewWSBridge constructs a bridge. backoffMin/backoffMax control reconnect
// backoff per target (default 1s / 30s if zero).
func NewWSBridge(logger *slog.Logger, sub WSSubscriber, hub *WSHub) *WSBridge {
	return &WSBridge{
		logger:     logger,
		sub:        sub,
		hub:        hub,
		backoffMin: time.Second,
		backoffMax: 30 * time.Second,
		cancels:    map[string]context.CancelFunc{},
	}
}

// Reconcile starts subscribers for any target in snap that isn't already
// connected and cancels subscribers for targets that have been removed.
func (b *WSBridge) Reconcile(ctx context.Context, snap Snapshot) {
	wanted := map[string]string{} // target -> engine
	for engine, targets := range snap.Routing {
		for _, t := range targets {
			wanted[t] = engine
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Stop subscriptions for removed targets.
	for target, cancel := range b.cancels {
		if _, ok := wanted[target]; !ok {
			cancel()
			delete(b.cancels, target)
		}
	}
	// Start new subscriptions.
	for target, engine := range wanted {
		if _, ok := b.cancels[target]; ok {
			continue
		}
		subCtx, cancel := context.WithCancel(ctx)
		b.cancels[target] = cancel
		go b.run(subCtx, target, engine)
	}
}

// Run reconciles immediately and then on every snapFn tick / Snapshot
// change. It blocks until ctx is cancelled.
func (b *WSBridge) Run(ctx context.Context, snapFn func() Snapshot, interval time.Duration) error {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	b.Reconcile(ctx, snapFn())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			b.mu.Lock()
			for _, cancel := range b.cancels {
				cancel()
			}
			b.cancels = map[string]context.CancelFunc{}
			b.mu.Unlock()
			return nil
		case <-t.C:
			b.Reconcile(ctx, snapFn())
		}
	}
}

func (b *WSBridge) run(ctx context.Context, target, engine string) {
	backoff := b.backoffMin
	for {
		if ctx.Err() != nil {
			return
		}
		msgs := make(chan rvclient.WSMessage, 64)
		// Pump messages into the hub from this channel until Subscribe returns.
		pumpDone := make(chan struct{})
		go func() {
			defer close(pumpDone)
			for m := range msgs {
				b.hub.Broadcast(FleetMessage{
					Target: target,
					Engine: engine,
					Type:   m.Type,
					Data:   m.Data,
				})
			}
		}()
		err := b.sub.Subscribe(ctx, target, msgs)
		close(msgs)
		<-pumpDone

		if ctx.Err() != nil {
			return
		}
		if err != nil {
			b.logger.Debug("ws.subscribe.error",
				"target", target, "engine", engine, "err", err.Error(),
				"backoff", backoff.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > b.backoffMax {
			backoff = b.backoffMax
		}
	}
}
