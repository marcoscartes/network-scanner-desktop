package search

import (
	"network-scanner-desktop/internal/database"
	"strconv"
	"strings"
)

// DeviceQuery represents a parsed search query
type DeviceQuery struct {
	Text    string   // General search text
	Tags    []string // tag:value
	Ports   []int    // port:80
	IsKnown *bool    // known:true/false
	Vendor  string   // vendor:apple
	Type    string   // type:server
	Group   string   // group:home
}

// Parse parses a search string into a DeviceQuery
func Parse(queryStr string) DeviceQuery {
	query := DeviceQuery{}
	parts := strings.Fields(queryStr)

	for _, part := range parts {
		if strings.Contains(part, ":") {
			kv := strings.SplitN(part, ":", 2)
			key := strings.ToLower(kv[0])
			value := kv[1]

			switch key {
			case "tag":
				query.Tags = append(query.Tags, value)
			case "port":
				if p, err := strconv.Atoi(value); err == nil {
					query.Ports = append(query.Ports, p)
				}
			case "known":
				k := value == "true" || value == "yes" || value == "1"
				query.IsKnown = &k
			case "vendor":
				query.Vendor = strings.ToLower(value)
			case "type":
				query.Type = strings.ToLower(value)
			case "group":
				query.Group = strings.ToLower(value)
			default:
				// Treat as general text if key is unknown
				if query.Text == "" {
					query.Text = part
				} else {
					query.Text += " " + part
				}
			}
		} else {
			if query.Text == "" {
				query.Text = part
			} else {
				query.Text += " " + part
			}
		}
	}

	return query
}

// Match checks if a device matches the query
func (q *DeviceQuery) Match(d *database.Device) bool {
	// Text Search (IP, MAC, Name, Vendor, Notes)
	if q.Text != "" {
		text := strings.ToLower(q.Text)
		match := strings.Contains(strings.ToLower(d.IP), text) ||
			strings.Contains(strings.ToLower(d.MAC), text) ||
			strings.Contains(strings.ToLower(d.CustomName), text) ||
			strings.Contains(strings.ToLower(d.Vendor), text) ||
			strings.Contains(strings.ToLower(d.Notes), text) ||
			strings.Contains(strings.ToLower(d.Type), text) ||
			strings.Contains(strings.ToLower(d.CustomType), text) ||
			strings.Contains(strings.ToLower(d.GroupName), text)

		if !match {
			return false
		}
	}

	// Tags
	for _, qTag := range q.Tags {
		found := false
		for _, dTag := range d.Tags {
			if strings.EqualFold(qTag, dTag) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Ports
	for _, qPort := range q.Ports {
		found := false
		for _, dPort := range d.OpenPorts {
			if qPort == dPort {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// IsKnown
	if q.IsKnown != nil {
		if *q.IsKnown != d.IsKnown {
			return false
		}
	}

	// Vendor
	if q.Vendor != "" {
		if !strings.Contains(strings.ToLower(d.Vendor), q.Vendor) {
			return false
		}
	}

	// Type
	if q.Type != "" {
		if !strings.EqualFold(q.Type, d.Type) && !strings.EqualFold(q.Type, d.CustomType) {
			return false
		}
	}

	// Group
	if q.Group != "" {
		if !strings.EqualFold(q.Group, d.GroupName) {
			return false
		}
	}

	return true
}

// Filter applies the query to a list of devices
func (q *DeviceQuery) Filter(devices []*database.Device) []*database.Device {
	filtered := make([]*database.Device, 0)
	for _, d := range devices {
		if q.Match(d) {
			filtered = append(filtered, d)
		}
	}
	return filtered
}
