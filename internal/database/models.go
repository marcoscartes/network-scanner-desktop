package database

import "time"

// Vulnerability represents a security finding
type Vulnerability struct {
	RuleID      string `json:"rule_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Solution    string `json:"solution"`
	MoreInfo    string `json:"more_info"`
	Port        int    `json:"port,omitempty"`
}

// Device represents a network device
type Device struct {
	ID              int             `json:"id"`
	MAC             string          `json:"mac"`
	IP              string          `json:"ip"`
	CustomName      string          `json:"custom_name"` // User-assigned name
	Vendor          string          `json:"vendor"`
	Type            string          `json:"type"`        // Auto-detected type
	CustomType      string          `json:"custom_type"` // User-assigned type
	IsKnown         bool            `json:"is_known"`    // Trusted/Known device
	Tags            []string        `json:"tags"`        // User tags
	GroupName       string          `json:"group_name"`  // Device group (e.g., IoT, Servers)
	Notes           string          `json:"notes"`
	OpenPorts       []int           `json:"open_ports"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	MetricsURLs     []string        `json:"metrics_urls"`
	LastSeen        time.Time       `json:"last_seen"`
	FirstSeen       time.Time       `json:"first_seen"`
}

// ScanProgress tracks the progress of a port scan
type ScanProgress struct {
	Status      string     `json:"status"`   // running, complete, error
	Progress    int        `json:"progress"` // 0-100
	CurrentPort int        `json:"current_port"`
	TotalPorts  int        `json:"total_ports"`
	OpenPorts   []int      `json:"open_ports"`
	PortsFound  int        `json:"ports_found"`
	StartTime   time.Time  `json:"start_time"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// ElapsedTime returns the elapsed time in seconds
func (sp *ScanProgress) ElapsedTime() float64 {
	if sp.EndTime != nil {
		return sp.EndTime.Sub(sp.StartTime).Seconds()
	}
	return time.Since(sp.StartTime).Seconds()
}

// Notification represents a system notification
type Notification struct {
	ID        int       `json:"id"`
	Type      string    `json:"type"` // new_device, disconnected, port_change, security_alert
	DeviceIP  string    `json:"device_ip"`
	DeviceMAC string    `json:"device_mac"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Read      bool      `json:"read"`
	Severity  string    `json:"severity"` // info, warning, critical
}

// NotificationConfig stores notification settings
type NotificationConfig struct {
	ID              int               `json:"id"`
	EnabledChannels []string          `json:"enabled_channels"` // console, system, webhook
	EmailConfig     map[string]string `json:"email_config"`
	TelegramConfig  map[string]string `json:"telegram_config"`
	WebhookURL      string            `json:"webhook_url"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// DeviceHistory records historical states of devices
type DeviceHistory struct {
	ID         int       `json:"id"`
	DeviceMAC  string    `json:"device_mac"`
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname"`
	Vendor     string    `json:"vendor"`
	OpenPorts  []int     `json:"open_ports"`
	Timestamp  time.Time `json:"timestamp"`
	ChangeType string    `json:"change_type"` // new, update, disconnect
}

// NetworkStats stores aggregated network statistics
type NetworkStats struct {
	ID                  int       `json:"id"`
	Date                time.Time `json:"date"`
	TotalDevices        int       `json:"total_devices"`
	NewDevices          int       `json:"new_devices"`
	DisconnectedDevices int       `json:"disconnected_devices"`
	TotalPorts          int       `json:"total_ports"`
	ActiveDevices       int       `json:"active_devices"`
}
