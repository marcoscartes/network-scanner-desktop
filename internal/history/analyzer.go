package history

import (
	"database/sql"
	"encoding/json"
	"network-scanner-desktop/internal/database"
	"time"
)

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

// GetMostActiveDevices returns the devices with the most history entries
func GetMostActiveDevices(limit int) ([]*database.Device, error) {
	query := `
		SELECT d.id, d.mac, d.ip, d.vendor, d.type, d.open_ports, d.metrics_urls, d.last_seen, COUNT(h.id) as activity_count
		FROM devices d
		LEFT JOIN device_history h ON d.mac = h.device_mac
		GROUP BY d.mac
		ORDER BY activity_count DESC
		LIMIT ?
	`

	rows, err := database.GetDB().Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*database.Device
	for rows.Next() {
		var device database.Device
		var openPortsJSON, metricsURLsJSON string
		var lastSeenUnix int64
		var activityCount int

		err := rows.Scan(&device.ID, &device.MAC, &device.IP, &device.Vendor,
			&device.Type, &openPortsJSON, &metricsURLsJSON, &lastSeenUnix, &activityCount)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(openPortsJSON), &device.OpenPorts)
		json.Unmarshal([]byte(metricsURLsJSON), &device.MetricsURLs)
		device.LastSeen = time.Unix(lastSeenUnix, 0)

		devices = append(devices, &device)
	}

	return devices, nil
}

// GetDeviceFirstSeen returns the first time a device was seen
func GetDeviceFirstSeen(mac string) (time.Time, error) {
	var timestampUnix int64

	query := `
		SELECT MIN(timestamp)
		FROM device_history
		WHERE device_mac = ?
	`

	err := database.GetDB().QueryRow(query, mac).Scan(&timestampUnix)
	if err != nil {
		if err == sql.ErrNoRows {
			// If no history, check current device
			var device *database.Device
			devices, err := database.GetAllDevices()
			if err == nil {
				for _, d := range devices {
					if d.MAC == mac {
						device = d
						break
					}
				}
				if device != nil {
					return device.LastSeen, nil
				}
			}
		}
		return time.Time{}, err
	}

	return time.Unix(timestampUnix, 0), nil
}

// GetDeviceLastSeen returns the last time a device was seen
func GetDeviceLastSeen(mac string) (time.Time, error) {
	var timestampUnix int64

	query := `
		SELECT MAX(timestamp)
		FROM device_history
		WHERE device_mac = ? AND change_type != 'disconnect'
	`

	err := database.GetDB().QueryRow(query, mac).Scan(&timestampUnix)
	if err != nil {
		if err == sql.ErrNoRows {
			// If no history, check current device
			devices, err := database.GetAllDevices()
			if err == nil {
				for _, d := range devices {
					if d.MAC == mac {
						return d.LastSeen, nil
					}
				}
			}
		}
		return time.Time{}, err
	}

	return time.Unix(timestampUnix, 0), nil
}

// GetPortChangeHistory returns a list of port changes for a device
func GetPortChangeHistory(mac string, days int) ([]PortChange, error) {
	startTime := time.Now().AddDate(0, 0, -days)

	query := `
		SELECT open_ports, timestamp
		FROM device_history
		WHERE device_mac = ? AND timestamp >= ?
		ORDER BY timestamp ASC
	`

	rows, err := database.GetDB().Query(query, mac, startTime.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var changes []PortChange
	var previousPorts []int

	for rows.Next() {
		var openPortsJSON string
		var timestampUnix int64

		if err := rows.Scan(&openPortsJSON, &timestampUnix); err != nil {
			continue
		}

		var currentPorts []int
		json.Unmarshal([]byte(openPortsJSON), &currentPorts)

		if len(previousPorts) > 0 {
			added, removed := comparePorts(previousPorts, currentPorts)
			if len(added) > 0 || len(removed) > 0 {
				changes = append(changes, PortChange{
					Timestamp:    time.Unix(timestampUnix, 0),
					PortsAdded:   added,
					PortsRemoved: removed,
				})
			}
		}

		previousPorts = currentPorts
	}

	return changes, nil
}

// PortChange represents a change in open ports
type PortChange struct {
	Timestamp    time.Time `json:"timestamp"`
	PortsAdded   []int     `json:"ports_added"`
	PortsRemoved []int     `json:"ports_removed"`
}

// comparePorts compares two port lists and returns added and removed ports
func comparePorts(old, new []int) (added, removed []int) {
	oldMap := make(map[int]bool)
	newMap := make(map[int]bool)

	for _, port := range old {
		oldMap[port] = true
	}
	for _, port := range new {
		newMap[port] = true
	}

	// Find added ports
	for _, port := range new {
		if !oldMap[port] {
			added = append(added, port)
		}
	}

	// Find removed ports
	for _, port := range old {
		if !newMap[port] {
			removed = append(removed, port)
		}
	}

	return added, removed
}

// GetNetworkGrowth calculates the network growth over time
func GetNetworkGrowth(days int) ([]NetworkGrowthPoint, error) {
	startDate := time.Now().AddDate(0, 0, -days)

	query := `
		SELECT date, total_devices, new_devices
		FROM network_stats
		WHERE date >= ?
		ORDER BY date ASC
	`

	rows, err := database.GetDB().Query(query, startDate.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var growth []NetworkGrowthPoint
	for rows.Next() {
		var point NetworkGrowthPoint
		var dateUnix int64

		err := rows.Scan(&dateUnix, &point.TotalDevices, &point.NewDevices)
		if err != nil {
			continue
		}

		point.Date = time.Unix(dateUnix, 0)
		growth = append(growth, point)
	}

	return growth, nil
}

// NetworkGrowthPoint represents a point in network growth over time
type NetworkGrowthPoint struct {
	Date         time.Time `json:"date"`
	TotalDevices int       `json:"total_devices"`
	NewDevices   int       `json:"new_devices"`
}
