//go:build !windows

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/zserge/lorca"
)

func launchUI(port string) {
	url := fmt.Sprintf("http://127.0.0.1:%s", port)

	ui, err := lorca.New(url, "", 1280, 850)
	if err != nil {
		log.Printf("Failed to launch Lorca: %v. Opening in browser.", err)
		openBrowser(url)
		return
	}
	defer ui.Close()

	ui.Bind("quitApp", func() {
		ui.Close()
		os.Exit(0)
	})

	<-ui.Done()
}
