package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// EventType represents the type of event being broadcast
type EventType string

const (
	EventPackageCached     EventType = "package_cached"
	EventPackageDeleted    EventType = "package_deleted"
	EventPackageDownloaded EventType = "package_downloaded"
	EventScanComplete      EventType = "scan_complete"
	EventStatsUpdate       EventType = "stats_update"
	EventSystemAlert       EventType = "system_alert"
)

// Event represents a WebSocket event message
type Event struct {
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Client represents a WebSocket client connection
type Client struct {
	conn          *websocket.Conn
	send          chan []byte
	server        *Server
	subscriptions map[EventType]bool
	mu            sync.RWMutex
}

// Server manages WebSocket connections and event broadcasting
type Server struct {
	clients    map[*Client]bool
	broadcast  chan Event
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
	upgrader   websocket.Upgrader
}

// Config holds WebSocket server configuration
type Config struct {
	ReadBufferSize  int
	WriteBufferSize int
	CheckOrigin     func(r *http.Request) bool
}

// NewServer creates a new WebSocket server
func NewServer(cfg Config) *Server {
	if cfg.CheckOrigin == nil {
		cfg.CheckOrigin = func(r *http.Request) bool {
			return true // Allow all origins by default
		}
	}

	server := &Server{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan Event, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  cfg.ReadBufferSize,
			WriteBufferSize: cfg.WriteBufferSize,
			CheckOrigin:     cfg.CheckOrigin,
		},
	}

	return server
}

// Start starts the WebSocket server event loop
func (s *Server) Start(ctx context.Context) {
	go s.run(ctx)
	log.Info().Msg("WebSocket server started")
}

// run handles client registration/unregistration and broadcasting
func (s *Server) run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("WebSocket server shutting down")
			s.closeAllClients()
			return

		case client := <-s.register:
			s.mu.Lock()
			s.clients[client] = true
			s.mu.Unlock()
			log.Debug().
				Int("total_clients", len(s.clients)).
				Msg("Client registered")

		case client := <-s.unregister:
			s.mu.Lock()
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				close(client.send)
			}
			s.mu.Unlock()
			log.Debug().
				Int("total_clients", len(s.clients)).
				Msg("Client unregistered")

		case event := <-s.broadcast:
			s.broadcastEvent(event)

		case <-ticker.C:
			// Ping all clients to keep connections alive
			s.pingClients()
		}
	}
}

// broadcastEvent sends an event to all subscribed clients
func (s *Server) broadcastEvent(event Event) {
	message, err := json.Marshal(event)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal event")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		// Check if client is subscribed to this event type
		client.mu.RLock()
		subscribed := len(client.subscriptions) == 0 || client.subscriptions[event.Type]
		client.mu.RUnlock()

		if subscribed {
			select {
			case client.send <- message:
			default:
				// Client send buffer full - close connection
				go func(c *Client) {
					s.unregister <- c
				}(client)
			}
		}
	}

	log.Debug().
		Str("event_type", string(event.Type)).
		Int("clients_notified", len(s.clients)).
		Msg("Event broadcast")
}

// pingClients sends ping messages to all connected clients
func (s *Server) pingClients() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		if err := client.conn.WriteControl(
			websocket.PingMessage,
			[]byte{},
			time.Now().Add(10*time.Second),
		); err != nil {
			log.Debug().Err(err).Msg("Failed to ping client")
			go func(c *Client) {
				s.unregister <- c
			}(client)
		}
	}
}

// closeAllClients closes all client connections
func (s *Server) closeAllClients() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for client := range s.clients {
		client.conn.Close() // #nosec G104 -- Cleanup, error not critical
		close(client.send)
	}
	s.clients = make(map[*Client]bool)
}

// Broadcast sends an event to all connected clients
func (s *Server) Broadcast(eventType EventType, data map[string]interface{}) {
	event := Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	select {
	case s.broadcast <- event:
	default:
		log.Warn().Msg("Broadcast channel full - dropping event")
	}
}

// HandleWebSocket upgrades HTTP connection to WebSocket
func (s *Server) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upgrade connection")
		return
	}

	client := &Client{
		conn:          conn,
		send:          make(chan []byte, 256),
		server:        s,
		subscriptions: make(map[EventType]bool),
	}

	s.register <- client

	// Start goroutines for reading and writing
	go client.readPump()
	go client.writePump()

	log.Info().
		Str("remote_addr", r.RemoteAddr).
		Msg("WebSocket connection established")
}

// readPump handles incoming messages from the client
func (c *Client) readPump() {
	defer func() {
		c.server.unregister <- c
		c.conn.Close() // #nosec G104 -- Cleanup, error not critical
	}()

	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second)) // #nosec G104 -- Websocket deadline
	c.conn.SetPongHandler(func(string) error {                   // #nosec G104 -- Websocket handler
		_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second)) // #nosec G104 -- Websocket deadline
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Error().Err(err).Msg("WebSocket read error")
			}
			break
		}

		// Handle client messages (subscriptions, etc.)
		c.handleMessage(message)
	}
}

// writePump handles outgoing messages to the client
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close() // #nosec G104 -- Cleanup, error not critical
	}()

	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) // #nosec G104 -- Websocket deadline, error not critical
			if !ok {
				// Channel closed
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{}) // #nosec G104 -- Websocket write
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			_, _ = w.Write(message) // #nosec G104 -- Websocket buffer write

			// Write any additional queued messages
			n := len(c.send)
			for i := 0; i < n; i++ {
				_, _ = w.Write([]byte{'\n'}) // #nosec G104 -- Websocket buffer write
				_, _ = w.Write(<-c.send)     // #nosec G104 -- Websocket buffer write
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) // #nosec G104 -- Websocket deadline, error not critical
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage processes incoming client messages
func (c *Client) handleMessage(message []byte) {
	var msg struct {
		Action string      `json:"action"`
		Data   interface{} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal client message")
		return
	}

	switch msg.Action {
	case "subscribe":
		c.handleSubscribe(msg.Data)
	case "unsubscribe":
		c.handleUnsubscribe(msg.Data)
	case "ping":
		c.sendPong()
	default:
		log.Warn().Str("action", msg.Action).Msg("Unknown client action")
	}
}

// handleSubscribe subscribes the client to specific event types
func (c *Client) handleSubscribe(data interface{}) {
	eventTypes, ok := data.([]interface{})
	if !ok {
		log.Error().Msg("Invalid subscribe data format")
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, et := range eventTypes {
		if eventType, ok := et.(string); ok {
			c.subscriptions[EventType(eventType)] = true
			log.Debug().
				Str("event_type", eventType).
				Msg("Client subscribed to event type")
		}
	}
}

// handleUnsubscribe unsubscribes the client from specific event types
func (c *Client) handleUnsubscribe(data interface{}) {
	eventTypes, ok := data.([]interface{})
	if !ok {
		log.Error().Msg("Invalid unsubscribe data format")
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, et := range eventTypes {
		if eventType, ok := et.(string); ok {
			delete(c.subscriptions, EventType(eventType))
			log.Debug().
				Str("event_type", eventType).
				Msg("Client unsubscribed from event type")
		}
	}
}

// sendPong sends a pong response to the client
func (c *Client) sendPong() {
	response := map[string]string{"type": "pong"}
	message, _ := json.Marshal(response)
	select {
	case c.send <- message:
	default:
	}
}

// GetConnectedClients returns the number of connected clients
func (s *Server) GetConnectedClients() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}
