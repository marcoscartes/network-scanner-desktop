package management

import (
	"encoding/json"
	"fmt"
	"network-scanner-desktop/internal/database"
)

// ExportDevices returns a JSON representation of all devices
func ExportDevices() ([]byte, error) {
	devices, err := database.GetAllDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal devices: %w", err)
	}

	return data, nil
}

// ImportDevices imports devices from a JSON representation
func ImportDevices(data []byte) (int, error) {
	var devices []*database.Device
	if err := json.Unmarshal(data, &devices); err != nil {
		return 0, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	count := 0
	for _, dev := range devices {
		// We use UpsertDevice to handle existing records
		// Note: UpsertDevice as currently implemented only updates non-custom fields
		// if the record exists. For a true "Import", we might want to update
		// custom fields too if they are present in the import.

		// Let's use a specialized function or update UpsertDevice logic?
		// For now, let's just use UpdateDeviceDetails if it exists,
		// or UpsertDevice for the base record.

		if err := database.UpsertDevice(dev); err != nil {
			continue
		}

		// If it's an import, we usually want to preserve the custom names, notes, etc.
		database.UpdateDeviceDetails(dev.MAC, dev.CustomName, dev.CustomType, dev.IsKnown, dev.Tags, dev.Notes, dev.GroupName)
		count++
	}

	return count, nil
}
