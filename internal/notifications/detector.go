package notifications

import (
	"fmt"
	"network-scanner-desktop/internal/database"
	"time"
)

// Change represents a detected change in the network
type Change struct {
	Type      string // new_device, disconnected, port_change
	Device    *database.Device
	OldDevice *database.Device
	Message   string
	Severity  string
	Timestamp time.Time
}

// Detector handles change detection in the network
type Detector struct {
	previousDevices map[string]*database.Device // MAC -> Device
}

// NewDetector creates a new change detector
func NewDetector() *Detector {
	return &Detector{
		previousDevices: make(map[string]*database.Device),
	}
}

// DetectNewDevice checks if a device is new
func (d *Detector) DetectNewDevice(device *database.Device) bool {
	_, exists := d.previousDevices[device.MAC]
	return !exists
}

// DetectDisconnectedDevice checks if a device has disconnected
// A device is considered disconnected if it hasn't been seen in the last scan
func (d *Detector) DetectDisconnectedDevice(device *database.Device) bool {
	// Check if device was in previous scan but not in current
	_, wasPresent := d.previousDevices[device.MAC]
	return wasPresent
}

// DetectPortChanges detects changes in open ports between old and new device states
func (d *Detector) DetectPortChanges(old, new *database.Device) []int {
	if old == nil || new == nil {
		return nil
	}

	// Create maps for easy lookup
	oldPorts := make(map[int]bool)
	for _, port := range old.OpenPorts {
		oldPorts[port] = true
	}

	newPorts := make(map[int]bool)
	for _, port := range new.OpenPorts {
		newPorts[port] = true
	}

	// Find ports that are in new but not in old (newly opened)
	var changedPorts []int
	for port := range newPorts {
		if !oldPorts[port] {
			changedPorts = append(changedPorts, port)
		}
	}

	// Find ports that are in old but not in new (closed)
	for port := range oldPorts {
		if !newPorts[port] {
			changedPorts = append(changedPorts, port)
		}
	}

	return changedPorts
}

// CompareDeviceStates compares old and new device states and returns detected changes
func (d *Detector) CompareDeviceStates(old, new []*database.Device) []Change {
	var changes []Change

	// Create maps for easy lookup
	oldDevices := make(map[string]*database.Device)
	for _, device := range old {
		oldDevices[device.MAC] = device
	}

	newDevices := make(map[string]*database.Device)
	for _, device := range new {
		newDevices[device.MAC] = device
	}

	// Detect new devices
	for mac, newDevice := range newDevices {
		if _, exists := oldDevices[mac]; !exists {
			changes = append(changes, Change{
				Type:      "new_device",
				Device:    newDevice,
				Message:   fmt.Sprintf("New device detected: %s (%s)", newDevice.IP, newDevice.Vendor),
				Severity:  "info",
				Timestamp: time.Now(),
			})
		}
	}

	// Detect disconnected devices
	for mac, oldDevice := range oldDevices {
		if _, exists := newDevices[mac]; !exists {
			changes = append(changes, Change{
				Type:      "disconnected",
				Device:    oldDevice,
				Message:   fmt.Sprintf("Device disconnected: %s (%s)", oldDevice.IP, oldDevice.Vendor),
				Severity:  "warning",
				Timestamp: time.Now(),
			})
		}
	}

	// Detect port changes
	for mac, newDevice := range newDevices {
		if oldDevice, exists := oldDevices[mac]; exists {
			changedPorts := d.DetectPortChanges(oldDevice, newDevice)
			if len(changedPorts) > 0 {
				changes = append(changes, Change{
					Type:      "port_change",
					Device:    newDevice,
					OldDevice: oldDevice,
					Message:   fmt.Sprintf("Port changes detected on %s: %v", newDevice.IP, changedPorts),
					Severity:  "warning",
					Timestamp: time.Now(),
				})
			}
		}
	}

	return changes
}

// UpdateState updates the detector's internal state with current devices
func (d *Detector) UpdateState(devices []*database.Device) {
	d.previousDevices = make(map[string]*database.Device)
	for _, device := range devices {
		// Create a copy to avoid reference issues
		deviceCopy := *device
		d.previousDevices[device.MAC] = &deviceCopy
	}
}

// GetPreviousDevices returns the previous device states
func (d *Detector) GetPreviousDevices() map[string]*database.Device {
	return d.previousDevices
}
