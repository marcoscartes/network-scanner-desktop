package scanner

import (
	"fmt"
	"log"
	"net"
	"network-scanner-desktop/internal/database"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DiscoverDevices discovers devices on the local network
func DiscoverDevices(ipRange string) ([]*database.Device, error) {
	// Parse network range
	_, ipnet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return nil, fmt.Errorf("invalid IP range: %w", err)
	}

	var devices []*database.Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Generate all IPs in range
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ipStr := ip.String()
		if strings.HasSuffix(ipStr, ".0") || strings.HasSuffix(ipStr, ".255") {
			continue
		}

		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()

			if isHostAlive(targetIP) {
				mac := getMACAddress(targetIP)
				device := &database.Device{
					IP:       targetIP,
					MAC:      mac,
					LastSeen: time.Now(),
				}

				mu.Lock()
				devices = append(devices, device)
				mu.Unlock()
			}
		}(ipStr)
	}

	wg.Wait()
	log.Printf("Discovered %d devices\n", len(devices))
	return devices, nil
}

// isHostAlive checks if a host is alive using ping
func isHostAlive(ip string) bool {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "500", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	err := cmd.Run()
	return err == nil
}

// getMACAddress gets the MAC address for an IP from ARP table
func getMACAddress(ip string) string {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("arp", "-a", ip)
	} else {
		cmd = exec.Command("arp", "-n", ip)
	}

	output, err := cmd.Output()
	if err != nil {
		return fmt.Sprintf("unknown_%s", ip)
	}

	// Parse MAC address from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.Contains(field, "-") || strings.Contains(field, ":") {
					mac := strings.ReplaceAll(field, "-", ":")
					return strings.ToLower(mac)
				}
			}
		}
	}

	return fmt.Sprintf("unknown_%s", ip)
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetLocalNetwork detects the local network range
func GetLocalNetwork() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "192.168.1.0/24", nil // Fallback
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP.To4()

	// Assume /24 network
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2]), nil
}
