package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"network-scanner-desktop/internal/database"
	"network-scanner-desktop/internal/management"
	"network-scanner-desktop/internal/scanner"
	"network-scanner-desktop/internal/search"
	"network-scanner-desktop/internal/security"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

//go:embed templates/index.html
var indexHTML string

//go:embed static
var staticFS embed.FS

var (
	scanState = make(map[string]*database.ScanProgress)
	stateMu   sync.RWMutex
)

// Server represents the web server
type Server struct {
	router    *mux.Router
	port      string
	wsManager *WSManager
}

// NewServer creates a new web server
func NewServer(port string) *Server {
	s := &Server{
		router:    mux.NewRouter(),
		port:      port,
		wsManager: NewWSManager(),
	}

	go s.wsManager.Run()
	// Load security rules
	security.LoadRules(security.GetDefaultRulesPath())

	s.setupRoutes()
	return s
}

// GetRouter returns the mux router
func (s *Server) GetRouter() *mux.Router {
	return s.router
}

// setupRoutes configures the HTTP routes
func (s *Server) setupRoutes() {
	s.router.HandleFunc("/", s.handleIndex).Methods("GET")
	s.router.HandleFunc("/api/devices", s.handleSearch).Methods("GET")
	s.router.HandleFunc("/api/devices/{mac}", s.handleUpdateDevice).Methods("PUT")
	s.router.HandleFunc("/api/devices/{mac}/check-vulnerabilities", s.handleCheckVulnerabilities).Methods("POST")

	// Static files
	s.router.PathPrefix("/static/").Handler(http.FileServer(http.FS(staticFS)))

	s.router.HandleFunc("/api/scan-all-ports/{ip}", s.handleScanAllPorts).Methods("POST")
	s.router.HandleFunc("/api/scan-progress/{ip}", s.handleScanProgress).Methods("GET")

	// Notification endpoints
	s.router.HandleFunc("/api/notifications", s.handleGetNotifications).Methods("GET")
	s.router.HandleFunc("/api/notifications/read-all", s.handleMarkAllNotificationsRead).Methods("POST")
	s.router.HandleFunc("/api/notifications/all", s.handleDeleteAllNotifications).Methods("DELETE")
	s.router.HandleFunc("/api/notifications/{id}/read", s.handleMarkNotificationRead).Methods("POST")
	s.router.HandleFunc("/api/notifications/{id}", s.handleDeleteNotification).Methods("DELETE")
	s.router.HandleFunc("/api/notifications/config", s.handleGetNotificationConfig).Methods("GET")
	s.router.HandleFunc("/api/notifications/config", s.handleUpdateNotificationConfig).Methods("PUT")

	// History and Statistics endpoints
	s.router.HandleFunc("/api/history/device/{mac}", s.handleGetDeviceHistory).Methods("GET")
	s.router.HandleFunc("/api/history/network", s.handleGetNetworkHistory).Methods("GET")
	s.router.HandleFunc("/api/stats/overview", s.handleGetStatsOverview).Methods("GET")
	s.router.HandleFunc("/api/stats/trends", s.handleGetNetworkTrends).Methods("GET")
	s.router.HandleFunc("/api/stats/uptime/{mac}", s.handleGetDeviceUptime).Methods("GET")

	// WebSocket endpoint
	s.router.HandleFunc("/ws", s.wsManager.HandleConnections)

	// Export/Import
	s.router.HandleFunc("/api/export", s.handleExport).Methods("GET")
	s.router.HandleFunc("/api/import", s.handleImport).Methods("POST")
}

// handleIndex renders the dashboard
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	devices, err := database.GetAllDevices()
	if err != nil {
		http.Error(w, "Failed to load devices", http.StatusInternalServerError)
		return
	}

	searchQuery := r.URL.Query().Get("q")
	if searchQuery != "" {
		q := search.Parse(searchQuery)
		devices = q.Filter(devices)
	}

	// Sort by IP address
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].IP < devices[j].IP
	})

	funcMap := template.FuncMap{
		"json": func(v interface{}) string {
			b, _ := json.Marshal(v)
			return string(b)
		},
		"add": func(a, b int) int {
			return a + b
		},
	}

	tmpl, err := template.New("index").Funcs(funcMap).Parse(indexHTML)
	if err != nil {
		log.Printf("Template parse error: %v", err)
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}

	// Calculate stats
	totalDevices := len(devices)
	activeDevices := 0
	knownDevices := 0
	unknownDevices := 0
	criticalRisks := 0
	totalSecurityScore := 0.0
	now := time.Now()
	oneDayAgo := now.Add(-24 * time.Hour)

	for _, d := range devices {
		if d.LastSeen.After(oneDayAgo) {
			activeDevices++
		}
		if d.IsKnown {
			knownDevices++
		} else {
			unknownDevices++
		}

		// Security stats
		deviceScore := 100.0
		for _, v := range d.Vulnerabilities {
			if v.Severity == "critical" || v.Severity == "high" {
				criticalRisks++
			}
			switch v.Severity {
			case "critical":
				deviceScore -= 60
			case "high":
				deviceScore -= 40
			case "medium":
				deviceScore -= 20
			case "low":
				deviceScore -= 10
			}
		}
		if deviceScore < 0 {
			deviceScore = 0
		}
		totalSecurityScore += deviceScore
	}

	networkSecurityScore := 100
	if totalDevices > 0 {
		networkSecurityScore = int(totalSecurityScore / float64(totalDevices))
	}

	data := map[string]interface{}{
		"devices":              devices,
		"query":                searchQuery,
		"totalDevices":         totalDevices,
		"activeDevices":        activeDevices,
		"knownDevices":         knownDevices,
		"unknownDevices":       unknownDevices,
		"criticalRisks":        criticalRisks,
		"networkSecurityScore": networkSecurityScore,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Template execute error: %v", err)
	}
}

// handleSearch returns a filtered list of devices in JSON format
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	devices, err := database.GetAllDevices()
	if err != nil {
		http.Error(w, "Failed to load devices", http.StatusInternalServerError)
		return
	}

	searchQuery := r.URL.Query().Get("q")
	if searchQuery != "" {
		q := search.Parse(searchQuery)
		devices = q.Filter(devices)
	}

	// Sort by IP address
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].IP < devices[j].IP
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

// handleScanAllPorts initiates a full port scan
func (s *Server) handleScanAllPorts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ip := vars["ip"]

	stateMu.Lock()
	if progress, exists := scanState[ip]; exists && progress.Status == "running" {
		stateMu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Scan already running for this IP",
		})
		return
	}

	// Initialize scan state
	scanState[ip] = &database.ScanProgress{
		Status:      "running",
		Progress:    0,
		CurrentPort: 0,
		TotalPorts:  65535,
		OpenPorts:   []int{},
		PortsFound:  0,
		StartTime:   time.Now(),
	}
	stateMu.Unlock()

	// Start scan in goroutine
	go func() {
		log.Printf("Starting full port scan for %s\n", ip)

		openPorts := scanner.ScanAllPorts(ip, func(current, total int, ports []int) {
			stateMu.Lock()
			if state, ok := scanState[ip]; ok {
				state.Progress = (current * 100) / total
				state.CurrentPort = current
				state.OpenPorts = ports
				state.PortsFound = len(ports)

				s.Broadcast(map[string]interface{}{
					"type": "scan_progress",
					"ip":   ip,
					"data": state,
				})
			}
			stateMu.Unlock()
		})

		// Mark as complete
		stateMu.Lock()
		if state, ok := scanState[ip]; ok {
			state.Status = "complete"
			state.Progress = 100
			now := time.Now()
			state.EndTime = &now
			state.OpenPorts = openPorts
			state.PortsFound = len(openPorts)

			s.Broadcast(map[string]interface{}{
				"type": "scan_complete",
				"ip":   ip,
				"data": state,
			})
		}
		stateMu.Unlock()

		// Update database and check vulnerabilities
		devices, _ := database.GetAllDevices()
		for _, device := range devices {
			if device.IP == ip {
				device.OpenPorts = openPorts

				// Check for vulnerabilities
				device.Vulnerabilities = security.CheckDevice(openPorts, device.Type)

				database.UpsertDevice(device)

				// Notify if critical vulnerabilities found
				for _, v := range device.Vulnerabilities {
					if v.Severity == "critical" || v.Severity == "high" {
						database.SaveNotification(&database.Notification{
							Type:      "security_alert",
							DeviceIP:  device.IP,
							DeviceMAC: device.MAC,
							Message:   fmt.Sprintf("Security Risk: %s detected on %s", v.Name, v.Severity),
							Timestamp: time.Now(),
							Read:      false,
							Severity:  v.Severity,
						})
						s.Broadcast(map[string]interface{}{
							"type": "notification_alert", // Special type for security
							"data": v,
						})
					}
				}
				break
			}
		}

		log.Printf("Full port scan complete for %s. Found %d open ports\n", ip, len(openPorts))
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "started",
		"ip":     ip,
	})
}

// handleScanProgress returns the progress of a port scan
func (s *Server) handleScanProgress(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ip := vars["ip"]

	stateMu.RLock()
	progress, exists := scanState[ip]
	stateMu.RUnlock()

	if !exists {
		http.Error(w, "No scan found for this IP", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"status":       progress.Status,
		"progress":     progress.Progress,
		"current_port": progress.CurrentPort,
		"total_ports":  progress.TotalPorts,
		"open_ports":   progress.OpenPorts,
		"ports_found":  progress.PortsFound,
		"elapsed_time": progress.ElapsedTime(),
	}

	json.NewEncoder(w).Encode(response)
}

// Start starts the web server
func (s *Server) Start() error {
	log.Printf("Starting web server on port %s\n", s.port)
	return http.ListenAndServe(":"+s.port, s.router)
}

// Broadcast sends a message to all connected WebSocket clients
func (s *Server) Broadcast(msg interface{}) {
	s.wsManager.Broadcast(msg)
}

// handleGetNotifications returns all notifications
func (s *Server) handleGetNotifications(w http.ResponseWriter, r *http.Request) {
	notifications, err := database.GetAllNotifications()
	if err != nil {
		http.Error(w, "Failed to load notifications", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifications)
}

// handleMarkNotificationRead marks a notification as read
func (s *Server) handleMarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var notificationID int
	_, err := fmt.Sscanf(id, "%d", &notificationID)
	if err != nil {
		http.Error(w, "Invalid notification ID", http.StatusBadRequest)
		return
	}

	err = database.MarkNotificationAsRead(notificationID)
	if err != nil {
		http.Error(w, "Failed to mark notification as read", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleDeleteNotification deletes a notification
func (s *Server) handleDeleteNotification(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var notificationID int
	_, err := fmt.Sscanf(id, "%d", &notificationID)
	if err != nil {
		http.Error(w, "Invalid notification ID", http.StatusBadRequest)
		return
	}

	err = database.DeleteNotification(notificationID)
	if err != nil {
		http.Error(w, "Failed to delete notification", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleGetNotificationConfig returns the notification configuration
func (s *Server) handleGetNotificationConfig(w http.ResponseWriter, r *http.Request) {
	config, err := database.GetNotificationConfig()
	if err != nil {
		http.Error(w, "Failed to load notification config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// handleUpdateNotificationConfig updates the notification configuration
func (s *Server) handleUpdateNotificationConfig(w http.ResponseWriter, r *http.Request) {
	var config database.NotificationConfig
	err := json.NewDecoder(r.Body).Decode(&config)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = database.SaveNotificationConfig(&config)
	if err != nil {
		http.Error(w, "Failed to save notification config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleGetDeviceHistory returns the history of a specific device
func (s *Server) handleGetDeviceHistory(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	// Get time range from query parameters (default: last 30 days)
	days := 30
	if daysParam := r.URL.Query().Get("days"); daysParam != "" {
		fmt.Sscanf(daysParam, "%d", &days)
	}

	from := time.Now().AddDate(0, 0, -days)
	to := time.Now()

	history, err := database.GetDeviceHistory(mac, from, to)
	if err != nil {
		http.Error(w, "Failed to load device history", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

// handleGetNetworkHistory returns the network history
func (s *Server) handleGetNetworkHistory(w http.ResponseWriter, r *http.Request) {
	// Get time range from query parameters (default: last 30 days)
	days := 30
	if daysParam := r.URL.Query().Get("days"); daysParam != "" {
		fmt.Sscanf(daysParam, "%d", &days)
	}

	trends, err := database.GetNetworkTrends(days)
	if err != nil {
		http.Error(w, "Failed to load network history", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(trends)
}

// handleGetStatsOverview returns an overview of network statistics
func (s *Server) handleGetStatsOverview(w http.ResponseWriter, r *http.Request) {
	devices, err := database.GetAllDevices()
	if err != nil {
		http.Error(w, "Failed to load devices", http.StatusInternalServerError)
		return
	}

	// Calculate statistics
	totalDevices := len(devices)
	activeDevices := 0
	totalPorts := 0
	now := time.Now()
	oneDayAgo := now.Add(-24 * time.Hour)

	for _, device := range devices {
		if device.LastSeen.After(oneDayAgo) {
			activeDevices++
		}
		totalPorts += len(device.OpenPorts)
	}

	// Get today's stats
	todayStats, _ := database.CalculateDailyStats(now)

	overview := map[string]interface{}{
		"total_devices":      totalDevices,
		"active_devices":     activeDevices,
		"total_ports":        totalPorts,
		"new_devices_today":  0,
		"disconnected_today": 0,
	}

	if todayStats != nil {
		overview["new_devices_today"] = todayStats.NewDevices
		overview["disconnected_today"] = todayStats.DisconnectedDevices
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(overview)
}

// handleGetNetworkTrends returns network trends over time
func (s *Server) handleGetNetworkTrends(w http.ResponseWriter, r *http.Request) {
	// Get number of days from query parameters (default: 30)
	days := 30
	if daysParam := r.URL.Query().Get("days"); daysParam != "" {
		fmt.Sscanf(daysParam, "%d", &days)
	}

	trends, err := database.GetNetworkTrends(days)
	if err != nil {
		http.Error(w, "Failed to load network trends", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(trends)
}

// handleGetDeviceUptime returns the uptime percentage of a device
func (s *Server) handleGetDeviceUptime(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	// Get period from query parameters (default: 7 days)
	days := 7
	if daysParam := r.URL.Query().Get("days"); daysParam != "" {
		fmt.Sscanf(daysParam, "%d", &days)
	}

	period := time.Duration(days) * 24 * time.Hour
	uptime, err := database.GetDeviceUptime(mac, period)
	if err != nil {
		http.Error(w, "Failed to calculate uptime", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"mac":    mac,
		"uptime": uptime,
		"period": days,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleUpdateDevice updates device details
func (s *Server) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	var req struct {
		CustomName string   `json:"custom_name"`
		CustomType string   `json:"custom_type"`
		IsKnown    bool     `json:"is_known"`
		Tags       []string `json:"tags"`
		Notes      string   `json:"notes"`
		GroupName  string   `json:"group_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := database.UpdateDeviceDetails(mac, req.CustomName, req.CustomType, req.IsKnown, req.Tags, req.Notes, req.GroupName); err != nil {
		http.Error(w, "Failed to update device: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleMarkAllNotificationsRead marks all notifications as read
func (s *Server) handleMarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	if err := database.MarkAllNotificationsAsRead(); err != nil {
		http.Error(w, "Failed to mark all as read", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleDeleteAllNotifications deletes all notifications
func (s *Server) handleDeleteAllNotifications(w http.ResponseWriter, r *http.Request) {
	if err := database.DeleteAllNotifications(); err != nil {
		http.Error(w, "Failed to delete all notifications", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleCheckVulnerabilities performs a vulnerability check on a specific device
func (s *Server) handleCheckVulnerabilities(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mac := vars["mac"]

	devices, err := database.GetAllDevices()
	if err != nil {
		http.Error(w, "Failed to load devices", http.StatusInternalServerError)
		return
	}

	var targetDevice *database.Device
	for _, d := range devices {
		if d.MAC == mac {
			targetDevice = d
			break
		}
	}

	if targetDevice == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	// Run vulnerability check
	vulns := security.CheckDevice(targetDevice.OpenPorts, targetDevice.Type)
	targetDevice.Vulnerabilities = vulns

	// Save back to database
	if err := database.UpsertDevice(targetDevice); err != nil {
		http.Error(w, "Failed to update device vulnerabilities", http.StatusInternalServerError)
		return
	}

	// Notify if critical vulnerabilities found
	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			database.SaveNotification(&database.Notification{
				Type:      "security_alert",
				DeviceIP:  targetDevice.IP,
				DeviceMAC: targetDevice.MAC,
				Message:   fmt.Sprintf("Security Risk: %s detected on %s", v.Name, v.Severity),
				Timestamp: time.Now(),
				Read:      false,
				Severity:  v.Severity,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "success",
		"vulnerabilities": vulns,
	})
}

// handleExport handles the device export
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	data, err := management.ExportDevices()
	if err != nil {
		http.Error(w, "Export failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=network_devices.json")
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleImport handles the device import
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form
	err := r.ParseMultipartForm(10 << 20) // 10MB max
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read file content
	content := make([]byte, 10<<20)
	n, _ := file.Read(content)
	content = content[:n]

	count, err := management.ImportDevices(content)
	if err != nil {
		http.Error(w, "Import failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"count":  count,
	})
}
