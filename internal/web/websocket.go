package web

import (
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins
	},
}

// WSManager manages WebSocket connections
type WSManager struct {
	clients   map[*websocket.Conn]bool
	broadcast chan interface{} // Accept any JSON-serializable object
	mu        sync.Mutex
}

// NewWSManager creates a new WebSocket manager
func NewWSManager() *WSManager {
	return &WSManager{
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan interface{}),
	}
}

// Run starts the message broadcasting loop
func (m *WSManager) Run() {
	for {
		msg := <-m.broadcast

		m.mu.Lock()
		for client := range m.clients {
			err := client.WriteJSON(msg)
			if err != nil {
				log.Printf("WS error: %v", err)
				client.Close()
				delete(m.clients, client)
			}
		}
		m.mu.Unlock()
	}
}

// HandleConnections handles new WebSocket requests
func (m *WSManager) HandleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS upgrade error: %v", err)
		return
	}

	m.mu.Lock()
	m.clients[ws] = true
	m.mu.Unlock()

	log.Println("New WebSocket client connected")

	// Keep alive loop
	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.clients, ws)
			m.mu.Unlock()
			ws.Close()
			log.Println("WebSocket client disconnected")
		}()

		for {
			_, _, err := ws.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}

// Broadcast sends a message to all connected clients
func (m *WSManager) Broadcast(msg interface{}) {
	// Non-blocking send to avoid hanging if Run loop is busy
	go func() {
		m.broadcast <- msg
	}()
}
