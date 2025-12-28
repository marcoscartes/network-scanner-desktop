package notifications

import (
	"fmt"
	"log"
	"network-scanner-desktop/internal/database"
	"sync"
	"time"
)

// Manager manages notifications and notifiers
type Manager struct {
	notifiers       []Notifier
	config          *database.NotificationConfig
	rateLimiter     *RateLimiter
	queue           chan *database.Notification
	mu              sync.RWMutex
	stopChan        chan struct{}
	enabledChannels map[string]bool
}

// RateLimiter prevents notification spam
type RateLimiter struct {
	notifications map[string]time.Time // key -> last notification time
	mu            sync.RWMutex
	minInterval   time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(minInterval time.Duration) *RateLimiter {
	return &RateLimiter{
		notifications: make(map[string]time.Time),
		minInterval:   minInterval,
	}
}

// ShouldNotify checks if a notification should be sent based on rate limiting
func (rl *RateLimiter) ShouldNotify(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	lastTime, exists := rl.notifications[key]
	if !exists {
		rl.notifications[key] = time.Now()
		return true
	}

	if time.Since(lastTime) >= rl.minInterval {
		rl.notifications[key] = time.Now()
		return true
	}

	return false
}

// NewManager creates a new notification manager
func NewManager() *Manager {
	config, err := database.GetNotificationConfig()
	if err != nil {
		log.Printf("Warning: Failed to load notification config, using defaults: %v", err)
		config = &database.NotificationConfig{
			EnabledChannels: []string{"console"},
			EmailConfig:     make(map[string]string),
			TelegramConfig:  make(map[string]string),
		}
	}

	manager := &Manager{
		notifiers:       []Notifier{},
		config:          config,
		rateLimiter:     NewRateLimiter(30 * time.Second), // Min 30 seconds between same notifications
		queue:           make(chan *database.Notification, 100),
		stopChan:        make(chan struct{}),
		enabledChannels: make(map[string]bool),
	}

	// Initialize enabled channels map
	for _, channel := range config.EnabledChannels {
		manager.enabledChannels[channel] = true
	}

	// Initialize notifiers based on config
	manager.initializeNotifiers()

	// Start queue processor
	go manager.processQueue()

	return manager
}

// initializeNotifiers sets up notifiers based on configuration
func (m *Manager) initializeNotifiers() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.notifiers = []Notifier{}

	// Always add console notifier if enabled
	if m.enabledChannels["console"] {
		m.notifiers = append(m.notifiers, NewConsoleNotifier())
	}

	// Add system notifier if enabled
	if m.enabledChannels["system"] {
		m.notifiers = append(m.notifiers, NewSystemNotifier())
	}

	// Add webhook notifier if enabled and configured
	if m.enabledChannels["webhook"] && m.config.WebhookURL != "" {
		m.notifiers = append(m.notifiers, NewWebhookNotifier(m.config.WebhookURL))
	}

	log.Printf("Initialized %d notifiers: ", len(m.notifiers))
	for _, notifier := range m.notifiers {
		log.Printf("  - %s", notifier.Name())
	}
}

// Notify sends a notification through all enabled channels
func (m *Manager) Notify(notification *database.Notification) error {
	// Create rate limit key based on type and device
	rateLimitKey := fmt.Sprintf("%s:%s", notification.Type, notification.DeviceMAC)

	// Check rate limiting
	if !m.rateLimiter.ShouldNotify(rateLimitKey) {
		log.Printf("Rate limited notification: %s", rateLimitKey)
		return nil
	}

	// Set timestamp if not set
	if notification.Timestamp.IsZero() {
		notification.Timestamp = time.Now()
	}

	// Save to database
	err := database.SaveNotification(notification)
	if err != nil {
		log.Printf("Failed to save notification to database: %v", err)
	}

	// Add to queue for async processing
	select {
	case m.queue <- notification:
		return nil
	default:
		return fmt.Errorf("notification queue is full")
	}
}

// processQueue processes notifications from the queue
func (m *Manager) processQueue() {
	for {
		select {
		case notification := <-m.queue:
			m.sendToNotifiers(notification)
		case <-m.stopChan:
			return
		}
	}
}

// sendToNotifiers sends a notification to all configured notifiers
func (m *Manager) sendToNotifiers(notification *database.Notification) {
	m.mu.RLock()
	notifiers := m.notifiers
	m.mu.RUnlock()

	for _, notifier := range notifiers {
		go func(n Notifier) {
			err := n.Send(notification)
			if err != nil {
				log.Printf("Failed to send notification via %s: %v", n.Name(), err)
			}
		}(notifier)
	}
}

// NotifyChange creates and sends a notification from a detected change
func (m *Manager) NotifyChange(change Change) error {
	notification := &database.Notification{
		Type:      change.Type,
		DeviceIP:  change.Device.IP,
		DeviceMAC: change.Device.MAC,
		Message:   change.Message,
		Severity:  change.Severity,
		Timestamp: change.Timestamp,
		Read:      false,
	}

	return m.Notify(notification)
}

// UpdateConfig updates the notification configuration
func (m *Manager) UpdateConfig(config *database.NotificationConfig) error {
	m.mu.Lock()
	m.config = config
	m.enabledChannels = make(map[string]bool)
	for _, channel := range config.EnabledChannels {
		m.enabledChannels[channel] = true
	}
	m.mu.Unlock()

	// Reinitialize notifiers with new config
	m.initializeNotifiers()

	// Save to database
	return database.SaveNotificationConfig(config)
}

// GetConfig returns the current notification configuration
func (m *Manager) GetConfig() *database.NotificationConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// Stop stops the notification manager
func (m *Manager) Stop() {
	close(m.stopChan)
}

// GetQueueSize returns the current queue size
func (m *Manager) GetQueueSize() int {
	return len(m.queue)
}
