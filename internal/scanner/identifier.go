package scanner

import (
	"fmt"
	"io"
	"net/http"
	"network-scanner-desktop/internal/database"
	"network-scanner-desktop/internal/devicevendor"
	"strings"
	"time"
)

// IdentifyDevice enriches device information
func IdentifyDevice(device *database.Device) {
	// Get vendor
	device.Vendor = devicevendor.LookupVendor(device.MAC)

	// Scan common ports
	device.OpenPorts = ScanCommonPorts(device.IP)

	// Identify device type based on open ports
	device.Type = identifyDeviceType(device.OpenPorts)

	// Check for metrics endpoints
	device.MetricsURLs = checkMetricsEndpoints(device.IP)
}

// identifyDeviceType identifies device type based on open ports
func identifyDeviceType(ports []int) string {
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	if portSet[9100] {
		return "Node Exporter"
	}
	if portSet[3389] {
		return "Windows PC"
	}
	if portSet[22] && !portSet[80] {
		return "Linux Server"
	}
	if portSet[445] {
		return "Windows/Samba"
	}
	if portSet[80] || portSet[443] {
		return "Web Server"
	}
	if portSet[1883] || portSet[8883] {
		return "MQTT Broker"
	}

	return "Unknown"
}

// checkMetricsEndpoints checks for Prometheus metrics endpoints
func checkMetricsEndpoints(ip string) []string {
	ports := []int{9100, 8080, 80, 3000, 8090, 9090}
	var metricsURLs []string

	client := &http.Client{Timeout: 1 * time.Second}

	for _, port := range ports {
		url := fmt.Sprintf("http://%s:%d/metrics", ip, port)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				content := string(body)
				if strings.Contains(content, "# HELP") || strings.Contains(content, "# TYPE") {
					metricsURLs = append(metricsURLs, url)
				}
			}
		}
	}

	return metricsURLs
}
