package raven

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// WSMessage mirrors raven's internal/api.WSMessage envelope.
type WSMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Subscribe opens a WebSocket to baseURL+"/ws" and writes every received
// message to out. It returns when ctx is cancelled or a fatal error occurs.
// Callers handle reconnect/backoff externally — Subscribe does not retry.
//
// The function uses the Client's HTTP timeout for the initial dial only;
// after dial, the connection is long-lived.
func (c *Client) Subscribe(ctx context.Context, baseURL string, out chan<- WSMessage) error {
	wsURL, err := toWSURL(baseURL)
	if err != nil {
		return err
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: c.timeout,
	}
	if c.tlsConfig != nil {
		dialer.TLSClientConfig = c.tlsConfig.Clone()
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, c.timeout)
	defer cancelDial()
	conn, _, err := dialer.DialContext(dialCtx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("ws dial %s: %w", wsURL, err)
	}
	defer conn.Close()

	conn.SetReadLimit(1 << 20) // 1 MiB per frame
	if err := conn.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
		return err
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	})
	conn.SetPingHandler(func(appData string) error {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteMessage(websocket.PongMessage, []byte(appData))
	})

	// Close the connection when the context is cancelled so ReadJSON unblocks.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(time.Second))
			_ = conn.Close()
		case <-done:
		}
	}()

	for {
		var msg WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("ws read %s: %w", wsURL, err)
		}
		select {
		case out <- msg:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// toWSURL rewrites http(s)://host/... to ws(s)://host/ws.
func toWSURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported ws base scheme %q", u.Scheme)
	}
	u.Path = "/ws"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
