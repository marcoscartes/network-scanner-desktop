package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"network-scanner-desktop/internal/database"
	"os/exec"
	"runtime"
	"time"
)

// Notifier is the interface for sending notifications
type Notifier interface {
	Send(notification *database.Notification) error
	Name() string
}

// ConsoleNotifier sends notifications to console/logs
type ConsoleNotifier struct{}

// NewConsoleNotifier creates a new console notifier
func NewConsoleNotifier() *ConsoleNotifier {
	return &ConsoleNotifier{}
}

// Name returns the notifier name
func (n *ConsoleNotifier) Name() string {
	return "console"
}

// Send sends a notification to the console
func (n *ConsoleNotifier) Send(notification *database.Notification) error {
	severityIcon := map[string]string{
		"info":     "ℹ️",
		"warning":  "⚠️",
		"critical": "🚨",
	}

	icon := severityIcon[notification.Severity]
	if icon == "" {
		icon = "📢"
	}

	log.Printf("%s [%s] %s - %s\n",
		icon,
		notification.Severity,
		notification.Type,
		notification.Message)

	return nil
}

// SystemNotifier sends native OS notifications
type SystemNotifier struct{}

// NewSystemNotifier creates a new system notifier
func NewSystemNotifier() *SystemNotifier {
	return &SystemNotifier{}
}

// Name returns the notifier name
func (n *SystemNotifier) Name() string {
	return "system"
}

// Send sends a native OS notification
func (n *SystemNotifier) Send(notification *database.Notification) error {
	switch runtime.GOOS {
	case "windows":
		return n.sendWindowsNotification(notification)
	case "darwin":
		return n.sendMacNotification(notification)
	case "linux":
		return n.sendLinuxNotification(notification)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// sendWindowsNotification sends a Windows toast notification
func (n *SystemNotifier) sendWindowsNotification(notification *database.Notification) error {
	// Use PowerShell to send Windows toast notification
	title := fmt.Sprintf("Network Scanner - %s", notification.Type)

	script := fmt.Sprintf(`
		[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
		[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

		$template = @"
<toast>
	<visual>
		<binding template="ToastText02">
			<text id="1">%s</text>
			<text id="2">%s</text>
		</binding>
	</visual>
</toast>
"@

		$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
		$xml.LoadXml($template)
		$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
		[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Network Scanner").Show($toast)
	`, title, notification.Message)

	cmd := exec.Command("powershell", "-Command", script)
	return cmd.Run()
}

// sendMacNotification sends a macOS notification
func (n *SystemNotifier) sendMacNotification(notification *database.Notification) error {
	title := fmt.Sprintf("Network Scanner - %s", notification.Type)
	cmd := exec.Command("osascript", "-e",
		fmt.Sprintf(`display notification "%s" with title "%s"`,
			notification.Message, title))
	return cmd.Run()
}

// sendLinuxNotification sends a Linux notification using notify-send
func (n *SystemNotifier) sendLinuxNotification(notification *database.Notification) error {
	title := fmt.Sprintf("Network Scanner - %s", notification.Type)
	cmd := exec.Command("notify-send", title, notification.Message)
	return cmd.Run()
}

// WebhookNotifier sends notifications via HTTP webhook
type WebhookNotifier struct {
	webhookURL string
	client     *http.Client
}

// NewWebhookNotifier creates a new webhook notifier
func NewWebhookNotifier(webhookURL string) *WebhookNotifier {
	return &WebhookNotifier{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns the notifier name
func (n *WebhookNotifier) Name() string {
	return "webhook"
}

// Send sends a notification via webhook
func (n *WebhookNotifier) Send(notification *database.Notification) error {
	if n.webhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}

	// Prepare payload
	payload := map[string]interface{}{
		"type":       notification.Type,
		"device_ip":  notification.DeviceIP,
		"device_mac": notification.DeviceMAC,
		"message":    notification.Message,
		"severity":   notification.Severity,
		"timestamp":  notification.Timestamp.Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send POST request
	req, err := http.NewRequest("POST", n.webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Network-Scanner/1.0")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
