//go:build windows

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/jchv/go-webview2"
)

func launchUI(port string) {
	url := fmt.Sprintf("http://127.0.0.1:%s", port)

	// Create a new webview window
	w := webview2.New(false)
	if w == nil {
		log.Println("Failed to create WebView2. Make sure Edge WebView2 Runtime is installed.")
		openBrowser(url)
		return
	}
	defer w.Destroy()

	w.SetTitle("Network Scanner")
	w.SetSize(1280, 850, webview2.HintNone)

	w.Navigate(url)

	// Bind quitApp function
	w.Bind("quitApp", func() {
		w.Terminate()
		os.Exit(0)
	})

	w.Run()
}
