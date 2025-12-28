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
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/zserge/lorca"
)

func main() {
	// Single instance check per user to prevent multiple windows opening
	// We try to listen on a specific port. If it's taken, another instance is running.
	lockPort := 5051
	lock, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", lockPort))
	if err != nil {
		log.Println("Another instance is already running. Exiting.")
		return
	}
	defer lock.Close()

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

	// Launch Lorca
	// This will open a standalone window using the installed Chrome/Edge
	ui, err := lorca.New(fmt.Sprintf("http://127.0.0.1:%s", port), "", 1280, 850)
	if err != nil {
		log.Printf("Failed to launch standalone window: %v. Opening in browser instead.", err)
		openBrowser(fmt.Sprintf("http://127.0.0.1:%s", port))
	} else {
		defer ui.Close()

		// Bind quitApp function to allow closing from JS
		ui.Bind("quitApp", func() {
			ui.Close()
			os.Exit(0)
		})
	}

	// Graceful shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)

	if ui != nil {
		select {
		case <-sigc:
		case <-ui.Done():
		}
	} else {
		<-sigc
	}

	log.Println("Application exiting...")
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = execCommand("xdg-open", url)
	case "windows":
		err = execCommand("rundll32", "url.dll,FileProtocolHandler", url)
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
