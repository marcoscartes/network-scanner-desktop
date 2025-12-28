package history

import (
	"database/sql"
	"encoding/json"
	"log"
	"network-scanner-desktop/internal/database"
	"time"
)

// Recorder handles recording of historical device states
type Recorder struct {
	db *sql.DB
}

// NewRecorder creates a new history recorder
func NewRecorder(db *sql.DB) *Recorder {
	return &Recorder{db: db}
}

// RecordDeviceState records the current state of a device
func RecordDeviceState(device *database.Device, changeType string) error {
	openPortsJSON, _ := json.Marshal(device.OpenPorts)

	query := `
		INSERT INTO device_history (device_mac, ip, hostname, vendor, open_ports, timestamp, change_type)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := database.GetDB().Exec(query,
		device.MAC,
		device.IP,
		"", // hostname - can be added later
		device.Vendor,
		string(openPortsJSON),
		time.Now().Unix(),
		changeType,
	)

	if err != nil {
		log.Printf("Failed to record device state: %v", err)
		return err
	}

	return nil
}

// RecordNetworkSnapshot records a snapshot of all devices in the network
func RecordNetworkSnapshot(devices []*database.Device) error {
	for _, device := range devices {
		err := RecordDeviceState(device, "snapshot")
		if err != nil {
			log.Printf("Failed to record snapshot for device %s: %v", device.MAC, err)
		}
	}
	return nil
}

// CalculateDailyStats calculates and stores daily statistics
func CalculateDailyStats(date time.Time) (*database.NetworkStats, error) {
	// Normalize date to start of day
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	endOfDay := startOfDay.Add(24 * time.Hour)

	stats := &database.NetworkStats{
		Date: startOfDay,
	}

	// Get total devices seen on this day
	err := database.GetDB().QueryRow(`
		SELECT COUNT(DISTINCT device_mac)
		FROM device_history
		WHERE timestamp >= ? AND timestamp < ?
	`, startOfDay.Unix(), endOfDay.Unix()).Scan(&stats.TotalDevices)

	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get new devices (first appearance)
	err = database.GetDB().QueryRow(`
		SELECT COUNT(DISTINCT device_mac)
		FROM device_history
		WHERE change_type = 'new'
		AND timestamp >= ? AND timestamp < ?
	`, startOfDay.Unix(), endOfDay.Unix()).Scan(&stats.NewDevices)

	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get disconnected devices
	err = database.GetDB().QueryRow(`
		SELECT COUNT(DISTINCT device_mac)
		FROM device_history
		WHERE change_type = 'disconnect'
		AND timestamp >= ? AND timestamp < ?
	`, startOfDay.Unix(), endOfDay.Unix()).Scan(&stats.DisconnectedDevices)

	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Get currently active devices
	devices, err := database.GetAllDevices()
	if err == nil {
		stats.ActiveDevices = len(devices)
		totalPorts := 0
		for _, device := range devices {
			totalPorts += len(device.OpenPorts)
		}
		stats.TotalPorts = totalPorts
	}

	// Save stats to database
	_, err = database.GetDB().Exec(`
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

// GetDeviceHistory retrieves the history of a specific device
func GetDeviceHistory(mac string, from, to time.Time) ([]*database.DeviceHistory, error) {
	query := `
		SELECT id, device_mac, ip, hostname, vendor, open_ports, timestamp, change_type
		FROM device_history
		WHERE device_mac = ? AND timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp DESC
	`

	rows, err := database.GetDB().Query(query, mac, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*database.DeviceHistory
	for rows.Next() {
		var h database.DeviceHistory
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
func GetNetworkTrends(days int) ([]*database.NetworkStats, error) {
	startDate := time.Now().AddDate(0, 0, -days)

	query := `
		SELECT id, date, total_devices, new_devices, disconnected_devices, total_ports, active_devices
		FROM network_stats
		WHERE date >= ?
		ORDER BY date ASC
	`

	rows, err := database.GetDB().Query(query, startDate.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trends []*database.NetworkStats
	for rows.Next() {
		var stat database.NetworkStats
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

// CleanOldHistory removes history entries older than the specified number of days
func CleanOldHistory(retentionDays int) error {
	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	_, err := database.GetDB().Exec(`
		DELETE FROM device_history WHERE timestamp < ?
	`, cutoffDate.Unix())

	if err != nil {
		log.Printf("Failed to clean old history: %v", err)
		return err
	}

	log.Printf("Cleaned history older than %d days", retentionDays)
	return nil
}
