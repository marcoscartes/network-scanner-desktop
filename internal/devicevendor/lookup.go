package devicevendor

import (
	"fmt"
	"io"
	"net/http"
	"network-scanner-desktop/internal/database"
	"strings"
	"time"
)

// LookupVendor looks up the vendor for a MAC address
func LookupVendor(mac string) string {
	if mac == "" || strings.HasPrefix(mac, "unknown_") {
		return "Unknown"
	}

	// Check cache first
	if vendor, ok := database.GetCachedVendor(mac); ok {
		return vendor
	}

	// Query API
	url := fmt.Sprintf("https://api.macvendors.com/%s", mac)
	client := &http.Client{Timeout: 3 * time.Second}
	
	resp, err := client.Get(url)
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "Unknown"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}

	vendor := strings.TrimSpace(string(body))
	
	// Save to cache
	database.SaveCachedVendor(mac, vendor)
	
	return vendor
}
