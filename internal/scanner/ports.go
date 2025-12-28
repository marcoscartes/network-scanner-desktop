package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// CommonPorts is the list of commonly scanned ports
var CommonPorts = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	25,    // SMTP
	53,    // DNS
	80,    // HTTP
	110,   // POP3
	143,   // IMAP
	443,   // HTTPS
	445,   // SMB
	3306,  // MySQL
	3389,  // RDP
	5432,  // PostgreSQL
	5900,  // VNC
	8080,  // HTTP Alt
	8090,  // HTTP Alt
	8443,  // HTTPS Alt
	9100,  // Prometheus Node Exporter
	1883,  // MQTT
	8883,  // MQTT over SSL
	3000,  // Node.js/React dev
	5000,  // Flask default
	5001,  // Synology DSM
	8000,  // Python HTTP
	8008,  // Google Home
	8081,  // Common alt HTTP
	8888,  // Jupyter
	9000,  // Portainer
	9090,  // Prometheus
}

// ScanPorts scans the specified ports on the given IP
func ScanPorts(ip string, ports []int, timeout time.Duration) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrent connections
	sem := make(chan struct{}, 100)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// ScanCommonPorts scans common ports on the given IP
func ScanCommonPorts(ip string) []int {
	return ScanPorts(ip, CommonPorts, 300*time.Millisecond)
}

// ScanAllPorts scans all ports (1-65535) on the given IP
func ScanAllPorts(ip string, progressCallback func(current, total int, openPorts []int)) []int {
	allPorts := make([]int, 65535)
	for i := range allPorts {
		allPorts[i] = i + 1
	}

	var openPorts []int
	var mu sync.Mutex

	chunkSize := 1000
	for i := 0; i < len(allPorts); i += chunkSize {
		end := i + chunkSize
		if end > len(allPorts) {
			end = len(allPorts)
		}

		chunk := allPorts[i:end]
		chunkOpen := ScanPorts(ip, chunk, 100*time.Millisecond)
		
		mu.Lock()
		openPorts = append(openPorts, chunkOpen...)
		mu.Unlock()

		if progressCallback != nil {
			progressCallback(end, len(allPorts), openPorts)
		}
	}

	return openPorts
}
