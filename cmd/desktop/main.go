package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"network-scanner-desktop/internal/database"
	"network-scanner-desktop/internal/history"
	"network-scanner-desktop/internal/scanner"
	"network-scanner-desktop/internal/web"
	"os"
	"os/exec"
	"runtime"
	"time"
)

var (
	instanceLock net.Listener
)

func main() {
	// Single instance check using a TCP port lock
	var err error
	instanceLock, err = net.Listen("tcp", "127.0.0.1:5055")
	if err != nil {
		log.Println("Another instance is already running. Exiting.")
		return
	}

	log.Printf("Application starting (PID: %d)", os.Getpid())

	// Initialize database
	dbPath := "scanner.db"
	if err := database.Init(dbPath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Setup web server on a random port for the internal UI
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	port := fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)
	log.Printf("Internal server running on http://127.0.0.1:%s", port)
	server := web.NewServer(port)

	go http.Serve(ln, server.GetRouter())

	// Start scanning loop in background
	go func() {
		for {
			log.Println("Starting background discovery...")
			ipRange, _ := scanner.GetLocalNetwork()
			devices, err := scanner.DiscoverDevices(ipRange)
			if err == nil {
				for _, d := range devices {
					// Identify device and save
					scanner.IdentifyDevice(d)
					database.UpsertDevice(d)

					// Record history
					history.RecordDeviceState(d, "snapshot")
				}

				// Calculate daily stats
				database.CalculateDailyStats(time.Now())

				// Broadcast update via WebSocket
				server.Broadcast(map[string]interface{}{
					"type": "discovery_complete",
				})
			}

			time.Sleep(5 * time.Minute)
		}
	}()

	// Launch UI
	// This will use WebView2 (no CGO) on Windows and Lorca on other platforms
	launchUI(port)

	log.Println("Application exiting...")
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = execCommand("xdg-open", url)
	case "windows":
		// 'start' command is safer than rundll32 for URLs
		err = execCommand("cmd", "/c", "start", "", url)
	case "darwin":
		err = execCommand("open", url)
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Printf("Could not open browser: %v", err)
	}
}

func execCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Start()
}
