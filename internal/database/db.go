package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB
var dbMu sync.Mutex

// GetDB returns the database connection
func GetDB() *sql.DB {
	return db
}

// Init initializes the database
func Init(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure SQLite for better concurrency
	// WAL mode allows multiple readers and one writer concurrently
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		log.Printf("Warning: failed to enable WAL mode: %v", err)
	}
	// busy_timeout makes SQLite wait for the specified time (5s) instead of failing immediately
	if _, err := db.Exec("PRAGMA busy_timeout=5000;"); err != nil {
		log.Printf("Warning: failed to set busy_timeout: %v", err)
	}

	// Limit connection pooling to avoid locking issues in some cases
	db.SetMaxOpenConns(1) // Keep it to 1 writer if not using a more complex setup, but WAL helps
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mac TEXT UNIQUE NOT NULL,
			ip TEXT NOT NULL,
			custom_name TEXT,
			vendor TEXT,
			type TEXT,
			custom_type TEXT,
			is_known INTEGER DEFAULT 0,
			tags TEXT,
			group_name TEXT,
			notes TEXT,
			open_ports TEXT,
			vulnerabilities TEXT,
			metrics_urls TEXT,
			last_seen INTEGER NOT NULL,
			first_seen INTEGER DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS vendor_cache (
			mac TEXT PRIMARY KEY,
			vendor TEXT NOT NULL,
			cached_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS notifications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			device_ip TEXT,
			device_mac TEXT,
			message TEXT NOT NULL,
			timestamp INTEGER NOT NULL,
			read INTEGER DEFAULT 0,
			severity TEXT DEFAULT 'info'
		);

		CREATE TABLE IF NOT EXISTS notification_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			enabled_channels TEXT,
			email_config TEXT,
			telegram_config TEXT,
			webhook_url TEXT,
			updated_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS device_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_mac TEXT NOT NULL,
			ip TEXT NOT NULL,
			hostname TEXT,
			vendor TEXT,
			open_ports TEXT,
			timestamp INTEGER NOT NULL,
			change_type TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS network_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			date INTEGER NOT NULL UNIQUE,
			total_devices INTEGER DEFAULT 0,
			new_devices INTEGER DEFAULT 0,
			disconnected_devices INTEGER DEFAULT 0,
			total_ports INTEGER DEFAULT 0,
			active_devices INTEGER DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS cve_cache (
			cve_id TEXT PRIMARY KEY,
			description TEXT,
			severity TEXT,
			base_score REAL,
			published_at TEXT,
			last_modified TEXT,
			cached_at INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
		CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
		CREATE INDEX IF NOT EXISTS idx_notifications_timestamp ON notifications(timestamp);
		CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
		CREATE INDEX IF NOT EXISTS idx_notifications_device_mac ON notifications(device_mac);
		CREATE INDEX IF NOT EXISTS idx_device_history_mac ON device_history(device_mac);
		CREATE INDEX IF NOT EXISTS idx_device_history_timestamp ON device_history(timestamp);
		CREATE INDEX IF NOT EXISTS idx_network_stats_date ON network_stats(date);
	`)

	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Migrate schema for existing tables
	migrations := []string{
		"ALTER TABLE devices ADD COLUMN custom_name TEXT",
		"ALTER TABLE devices ADD COLUMN custom_type TEXT",
		"ALTER TABLE devices ADD COLUMN tags TEXT",
		"ALTER TABLE devices ADD COLUMN notes TEXT",
		"ALTER TABLE devices ADD COLUMN is_known INTEGER DEFAULT 0",
		"ALTER TABLE devices ADD COLUMN first_seen INTEGER DEFAULT 0",
		"ALTER TABLE devices ADD COLUMN vulnerabilities TEXT",
		"ALTER TABLE devices ADD COLUMN group_name TEXT",
	}

	for _, query := range migrations {
		if _, err := db.Exec(query); err == nil {
			log.Printf("Applied migration: %s", query)
		}
	}

	// Backfill first_seen
	db.Exec("UPDATE devices SET first_seen = last_seen WHERE first_seen = 0 OR first_seen IS NULL")

	log.Println("Database initialized successfully")
	return nil
}

// UpsertDevice inserts or updates a device
func UpsertDevice(device *Device) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	openPortsJSON, _ := json.Marshal(device.OpenPorts)
	vulnerabilitiesJSON, _ := json.Marshal(device.Vulnerabilities)
	metricsURLsJSON, _ := json.Marshal(device.MetricsURLs)

	// For new devices, first_seen should be set to last_seen/now
	// For existing devices, we do NOT update custom fields
	_, err := db.Exec(`
		INSERT INTO devices (mac, ip, vendor, type, open_ports, vulnerabilities, metrics_urls, last_seen, first_seen, group_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			ip = excluded.ip,
			vendor = excluded.vendor,
			type = excluded.type,
			open_ports = excluded.open_ports,
			vulnerabilities = excluded.vulnerabilities,
			metrics_urls = excluded.metrics_urls,
			last_seen = excluded.last_seen
	`, device.MAC, device.IP, device.Vendor, device.Type,
		string(openPortsJSON), string(vulnerabilitiesJSON), string(metricsURLsJSON), device.LastSeen.Unix(), device.LastSeen.Unix(), device.GroupName)

	return err
}

// GetAllDevices retrieves all devices from the database
func GetAllDevices() ([]*Device, error) {
	rows, err := db.Query(`
		SELECT id, mac, ip, custom_name, vendor, type, custom_type, is_known, tags, notes, open_ports, vulnerabilities, metrics_urls, last_seen, first_seen, group_name
		FROM devices
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		var device Device
		var openPortsJSON, vulnerabilitiesJSON, metricsURLsJSON string
		var tagsJSON sql.NullString
		var customName, customType, notes, groupName sql.NullString
		var lastSeenUnix int64
		var firstSeenUnix sql.NullInt64

		err := rows.Scan(&device.ID, &device.MAC, &device.IP, &customName, &device.Vendor,
			&device.Type, &customType, &device.IsKnown, &tagsJSON, &notes, &openPortsJSON, &vulnerabilitiesJSON, &metricsURLsJSON, &lastSeenUnix, &firstSeenUnix, &groupName)
		if err != nil {
			continue
		}

		if customName.Valid {
			device.CustomName = customName.String
		}
		if customType.Valid {
			device.CustomType = customType.String
		}
		if notes.Valid {
			device.Notes = notes.String
		}
		if groupName.Valid {
			device.GroupName = groupName.String
		}
		if tagsJSON.Valid {
			json.Unmarshal([]byte(tagsJSON.String), &device.Tags)
		}

		json.Unmarshal([]byte(openPortsJSON), &device.OpenPorts)
		json.Unmarshal([]byte(vulnerabilitiesJSON), &device.Vulnerabilities)
		json.Unmarshal([]byte(metricsURLsJSON), &device.MetricsURLs)
		device.LastSeen = time.Unix(lastSeenUnix, 0)
		if firstSeenUnix.Valid {
			device.FirstSeen = time.Unix(firstSeenUnix.Int64, 0)
		} else {
			device.FirstSeen = device.LastSeen // Fallback
		}

		devices = append(devices, &device)
	}

	return devices, nil
}

// UpdateDeviceDetails updates the user-configurable details of a device
func UpdateDeviceDetails(mac string, customName string, customType string, isKnown bool, tags []string, notes string, groupName string) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	tagsJSON, _ := json.Marshal(tags)

	result, err := db.Exec(`
		UPDATE devices 
		SET custom_name = ?, custom_type = ?, is_known = ?, tags = ?, notes = ?, group_name = ?
		WHERE mac = ?
	`, customName, customType, isKnown, string(tagsJSON), notes, groupName, mac)

	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("device not found")
	}

	return nil
}

// GetCachedVendor retrieves a cached vendor lookup
func GetCachedVendor(mac string) (string, bool) {
	var vendor string
	err := db.QueryRow("SELECT vendor FROM vendor_cache WHERE mac = ?", mac).Scan(&vendor)
	if err != nil {
		return "", false
	}
	return vendor, true
}

// SaveCachedVendor saves a vendor lookup to cache
func SaveCachedVendor(mac, vendor string) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec(`
		INSERT OR REPLACE INTO vendor_cache (mac, vendor, cached_at)
		VALUES (?, ?, ?)
	`, mac, vendor, time.Now().Unix())
	return err
}

// Close closes the database connection
func Close() error {
	if db != nil {
		return db.Close()
	}
	return nil
}

// SaveNotification saves a notification to the database
func SaveNotification(notification *Notification) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	result, err := db.Exec(`
		INSERT INTO notifications (type, device_ip, device_mac, message, timestamp, read, severity)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, notification.Type, notification.DeviceIP, notification.DeviceMAC,
		notification.Message, notification.Timestamp.Unix(), notification.Read, notification.Severity)

	if err != nil {
		return err
	}

	id, _ := result.LastInsertId()
	notification.ID = int(id)
	return nil
}

// GetAllNotifications retrieves all notifications
func GetAllNotifications() ([]*Notification, error) {
	rows, err := db.Query(`
		SELECT id, type, device_ip, device_mac, message, timestamp, read, severity
		FROM notifications
		ORDER BY timestamp DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notifications []*Notification
	for rows.Next() {
		var notification Notification
		var timestampUnix int64
		var readInt int

		err := rows.Scan(&notification.ID, &notification.Type, &notification.DeviceIP,
			&notification.DeviceMAC, &notification.Message, &timestampUnix, &readInt, &notification.Severity)
		if err != nil {
			continue
		}

		notification.Timestamp = time.Unix(timestampUnix, 0)
		notification.Read = readInt == 1

		notifications = append(notifications, &notification)
	}

	return notifications, nil
}

// GetUnreadNotifications retrieves unread notifications
func GetUnreadNotifications() ([]*Notification, error) {
	rows, err := db.Query(`
		SELECT id, type, device_ip, device_mac, message, timestamp, read, severity
		FROM notifications
		WHERE read = 0
		ORDER BY timestamp DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notifications []*Notification
	for rows.Next() {
		var notification Notification
		var timestampUnix int64
		var readInt int

		err := rows.Scan(&notification.ID, &notification.Type, &notification.DeviceIP,
			&notification.DeviceMAC, &notification.Message, &timestampUnix, &readInt, &notification.Severity)
		if err != nil {
			continue
		}

		notification.Timestamp = time.Unix(timestampUnix, 0)
		notification.Read = readInt == 1

		notifications = append(notifications, &notification)
	}

	return notifications, nil
}

// MarkNotificationAsRead marks a notification as read
func MarkNotificationAsRead(id int) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec("UPDATE notifications SET read = 1 WHERE id = ?", id)
	return err
}

// DeleteNotification deletes a notification
func DeleteNotification(id int) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec("DELETE FROM notifications WHERE id = ?", id)
	return err
}

// MarkAllNotificationsAsRead marks all notifications as read
func MarkAllNotificationsAsRead() error {
	dbMu.Lock()
	defer dbMu.Unlock()
	_, err := db.Exec("UPDATE notifications SET read = 1 WHERE read = 0")
	return err
}

// DeleteAllNotifications deletes all notifications
func DeleteAllNotifications() error {
	dbMu.Lock()
	defer dbMu.Unlock()
	_, err := db.Exec("DELETE FROM notifications")
	return err
}

// DeleteOldNotifications deletes notifications older than N days
func DeleteOldNotifications(days int) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -days).Unix()
	_, err := db.Exec("DELETE FROM notifications WHERE timestamp < ?", cutoff)
	return err
}

// GetNotificationConfig retrieves the notification configuration
func GetNotificationConfig() (*NotificationConfig, error) {
	var config NotificationConfig
	var enabledChannelsJSON, emailConfigJSON, telegramConfigJSON string
	var updatedAtUnix int64

	err := db.QueryRow(`
		SELECT id, enabled_channels, email_config, telegram_config, webhook_url, updated_at
		FROM notification_config
		ORDER BY id DESC
		LIMIT 1
	`).Scan(&config.ID, &enabledChannelsJSON, &emailConfigJSON, &telegramConfigJSON,
		&config.WebhookURL, &updatedAtUnix)

	if err == sql.ErrNoRows {
		// Return default config if none exists
		return &NotificationConfig{
			EnabledChannels: []string{"console"},
			EmailConfig:     make(map[string]string),
			TelegramConfig:  make(map[string]string),
			WebhookURL:      "",
			UpdatedAt:       time.Now(),
		}, nil
	}

	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(enabledChannelsJSON), &config.EnabledChannels)
	json.Unmarshal([]byte(emailConfigJSON), &config.EmailConfig)
	json.Unmarshal([]byte(telegramConfigJSON), &config.TelegramConfig)
	config.UpdatedAt = time.Unix(updatedAtUnix, 0)

	return &config, nil
}

// SaveNotificationConfig saves the notification configuration
func SaveNotificationConfig(config *NotificationConfig) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	enabledChannelsJSON, _ := json.Marshal(config.EnabledChannels)
	emailConfigJSON, _ := json.Marshal(config.EmailConfig)
	telegramConfigJSON, _ := json.Marshal(config.TelegramConfig)

	_, err := db.Exec(`
		INSERT INTO notification_config (enabled_channels, email_config, telegram_config, webhook_url, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, string(enabledChannelsJSON), string(emailConfigJSON), string(telegramConfigJSON),
		config.WebhookURL, time.Now().Unix())

	return err
}

// GetDeviceHistory retrieves the history of a specific device
func GetDeviceHistory(mac string, from, to time.Time) ([]*DeviceHistory, error) {
	query := `
		SELECT id, device_mac, ip, hostname, vendor, open_ports, timestamp, change_type
		FROM device_history
		WHERE device_mac = ? AND timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp DESC
	`

	rows, err := db.Query(query, mac, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*DeviceHistory
	for rows.Next() {
		var h DeviceHistory
		var openPortsJSON string
		var timestampUnix int64
		var hostname sql.NullString

		err := rows.Scan(&h.ID, &h.DeviceMAC, &h.IP, &hostname, &h.Vendor,
			&openPortsJSON, &timestampUnix, &h.ChangeType)
		if err != nil {
			continue
		}

		if hostname.Valid {
			h.Hostname = hostname.String
		}

		json.Unmarshal([]byte(openPortsJSON), &h.OpenPorts)
		h.Timestamp = time.Unix(timestampUnix, 0)

		history = append(history, &h)
	}

	return history, nil
}

// GetNetworkTrends retrieves network statistics for the last N days
func GetNetworkTrends(days int) ([]*NetworkStats, error) {
	startDate := time.Now().AddDate(0, 0, -days)

	query := `
		SELECT id, date, total_devices, new_devices, disconnected_devices, total_ports, active_devices
		FROM network_stats
		WHERE date >= ?
		ORDER BY date ASC
	`

	rows, err := db.Query(query, startDate.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trends []*NetworkStats
	for rows.Next() {
		var stat NetworkStats
		var dateUnix int64

		err := rows.Scan(&stat.ID, &dateUnix, &stat.TotalDevices, &stat.NewDevices,
			&stat.DisconnectedDevices, &stat.TotalPorts, &stat.ActiveDevices)
		if err != nil {
			continue
		}

		stat.Date = time.Unix(dateUnix, 0)
		trends = append(trends, &stat)
	}

	return trends, nil
}

// CalculateDailyStats calculates and stores daily statistics
func CalculateDailyStats(date time.Time) (*NetworkStats, error) {
	// Normalize date to start of day
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	endOfDay := startOfDay.Add(24 * time.Hour)

	stats := &NetworkStats{
		Date: startOfDay,
	}

	// Get total devices seen on this day
	err := db.QueryRow(`
		SELECT COUNT(DISTINCT device_mac)
		FROM device_history
		WHERE timestamp >= ? AND timestamp < ?
	`, startOfDay.Unix(), endOfDay.Unix()).Scan(&stats.TotalDevices)

	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get new devices (first appearance)
	err = db.QueryRow(`
		SELECT COUNT(DISTINCT device_mac)
		FROM device_history
		WHERE change_type = 'new'
		AND timestamp >= ? AND timestamp < ?
	`, startOfDay.Unix(), endOfDay.Unix()).Scan(&stats.NewDevices)

	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get disconnected devices
	err = db.QueryRow(`
		SELECT COUNT(DISTINCT device_mac)
		FROM device_history
		WHERE change_type = 'disconnect'
		AND timestamp >= ? AND timestamp < ?
	`, startOfDay.Unix(), endOfDay.Unix()).Scan(&stats.DisconnectedDevices)

	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get currently active devices
	devices, err := GetAllDevices()
	if err == nil {
		stats.ActiveDevices = len(devices)
		totalPorts := 0
		for _, device := range devices {
			totalPorts += len(device.OpenPorts)
		}
		stats.TotalPorts = totalPorts
	}

	// Save stats to database
	_, err = db.Exec(`
		INSERT OR REPLACE INTO network_stats 
		(date, total_devices, new_devices, disconnected_devices, total_ports, active_devices)
		VALUES (?, ?, ?, ?, ?, ?)
	`, startOfDay.Unix(), stats.TotalDevices, stats.NewDevices,
		stats.DisconnectedDevices, stats.TotalPorts, stats.ActiveDevices)

	if err != nil {
		log.Printf("Failed to save daily stats: %v", err)
		return nil, err
	}

	return stats, nil
}

// GetDeviceUptime calculates the uptime percentage of a device over a period
func GetDeviceUptime(mac string, period time.Duration) (float64, error) {
	startTime := time.Now().Add(-period)

	// Get all history records for this device in the period
	history, err := GetDeviceHistory(mac, startTime, time.Now())
	if err != nil {
		return 0, err
	}

	if len(history) == 0 {
		return 0, nil
	}

	// Count how many times the device was seen (not disconnected)
	activeCount := 0
	totalCount := len(history)

	for _, record := range history {
		if record.ChangeType != "disconnect" {
			activeCount++
		}
	}

	uptime := (float64(activeCount) / float64(totalCount)) * 100.0
	return uptime, nil
}

// SaveCVECache saves a CVE to the cache
func SaveCVECache(cveID, description, severity string, score float64, published, modified string) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec(`
		INSERT OR REPLACE INTO cve_cache (cve_id, description, severity, base_score, published_at, last_modified, cached_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, cveID, description, severity, score, published, modified, time.Now().Unix())
	return err
}

// GetCVECache retrieves a CVE from the cache
func GetCVECache(cveID string) (map[string]interface{}, bool) {
	var description, severity, published, modified string
	var score float64
	var cachedAt int64

	err := db.QueryRow(`
		SELECT description, severity, base_score, published_at, last_modified, cached_at 
		FROM cve_cache WHERE cve_id = ?
	`, cveID).Scan(&description, &severity, &score, &published, &modified, &cachedAt)

	if err != nil {
		return nil, false
	}

	// Check if cache is older than 30 days
	if time.Since(time.Unix(cachedAt, 0)) > 30*24*time.Hour {
		return nil, false
	}

	return map[string]interface{}{
		"cve_id":        cveID,
		"description":   description,
		"severity":      severity,
		"base_score":    score,
		"published_at":  published,
		"last_modified": modified,
	}, true
}
