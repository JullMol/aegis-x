package main

import (
	"aegis-x/internal/bridge"
	"aegis-x/internal/scanner"
	"aegis-x/internal/sniffer"
	"context"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/google/gopacket/pcap"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx context.Context
}

var cancelSniff context.CancelFunc

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) ScanDevicePorts(ip string) []scanner.PortResult {
	return scanner.ScanPorts(ip)
}

func (a *App) StartNetworkScan() ([]scanner.Device, error) {
	return scanner.ScanRealNetwork()
}

func (a *App) GetSecurityAnalysis(ports []scanner.PortResult, packets []sniffer.PacketInfo) bridge.AnalysisResult {
	result, err := bridge.AnalyzeWithPython(ports, packets)
	if err != nil {
		return bridge.AnalysisResult{}
	}
	return result
}

// Fitur 1: Intrusion Kill Chain (Firewall Block)
func (a *App) BlockIPAddress(ip string) string {
	if runtime.GOOS == "windows" {
		// Rule name unik agar tidak bentrok
		ruleName := fmt.Sprintf("AEGIS_BLOCK_%s", ip)

		// Method 1: Coba langsung (jika sudah admin)
		cmdDirect := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=in", "action=block", "remoteip="+ip)
		errDirect := cmdDirect.Run()

		if errDirect == nil {
			// Tambahkan rule outbound juga
			exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
				"name="+ruleName+"_OUT", "dir=out", "action=block", "remoteip="+ip).Run()
			return "SUCCESS: IP " + ip + " telah diblokir secara permanen."
		}

		// Method 2: Jika gagal, coba dengan UAC elevation via PowerShell
		psScript := fmt.Sprintf(`
			Start-Process -FilePath "netsh" -ArgumentList "advfirewall firewall add rule name=%s dir=in action=block remoteip=%s" -Verb RunAs -Wait
			Start-Process -FilePath "netsh" -ArgumentList "advfirewall firewall add rule name=%s_OUT dir=out action=block remoteip=%s" -Verb RunAs -Wait
		`, ruleName, ip, ruleName, ip)

		cmdPS := exec.Command("powershell", "-NoProfile", "-Command", psScript)
		errPS := cmdPS.Run()

		if errPS != nil {
			return "Gagal: Klik 'Yes' pada pop-up UAC, atau jalankan aplikasi sebagai Administrator."
		}
		return "SUCCESS: IP " + ip + " telah diblokir (via UAC elevation)."
	} else {
		// Untuk Linux (iptables)
		cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		err := cmd.Run()
		if err != nil {
			return "Error: Jalankan aplikasi sebagai Root."
		}
		return "SUCCESS: IP " + ip + " telah diblokir."
	}
}

// Global variable to track sniffer status
var isSniffing bool

func (a *App) StartLiveSniffing() {
	// Jika sniffer sudah berjalan, abaikan
	if isSniffing {
		fmt.Println("[Sniffer] Already running, skipping...")
		return
	}

	// Buat context baru yang bisa di-cancel
	var ctx context.Context
	ctx, cancelSniff = context.WithCancel(context.Background())

	// Ambil semua device yang dikenali oleh Npcap
	devices, err := pcap.FindAllDevs()
	if err != nil || len(devices) == 0 {
		fmt.Println("[Sniffer] ERROR: Gagal menemukan device pcap:", err)
		wailsRuntime.EventsEmit(a.ctx, "sniffer_error", "Tidak ada network device ditemukan. Pastikan Npcap terinstall.")
		return
	}

	// Debug: Print semua device yang ditemukan
	fmt.Println("[Sniffer] Available devices:")
	for i, d := range devices {
		fmt.Printf("  [%d] %s\n", i, d.Name)
		for _, addr := range d.Addresses {
			fmt.Printf("      IP: %s\n", addr.IP.String())
		}
	}

	localIP, _, _, _ := scanner.GetLocalIP()
	fmt.Println("[Sniffer] Local IP detected:", localIP)

	var targetDevice string

	// Method 1: Cari device pcap yang memiliki IP yang sama dengan IP lokal
	for _, d := range devices {
		for _, addr := range d.Addresses {
			if addr.IP.String() == localIP.String() {
				targetDevice = d.Name
				fmt.Println("[Sniffer] Found matching device:", targetDevice)
				break
			}
		}
		if targetDevice != "" {
			break
		}
	}

	// Method 2: Fallback - pilih device pertama yang punya IP address
	if targetDevice == "" {
		fmt.Println("[Sniffer] No exact match, trying fallback...")
		for _, d := range devices {
			if len(d.Addresses) > 0 {
				// Skip loopback
				if d.Addresses[0].IP.String() != "127.0.0.1" {
					targetDevice = d.Name
					fmt.Println("[Sniffer] Using fallback device:", targetDevice)
					break
				}
			}
		}
	}

	// Method 3: Last resort - pakai device pertama
	if targetDevice == "" && len(devices) > 0 {
		targetDevice = devices[0].Name
		fmt.Println("[Sniffer] Using first device as last resort:", targetDevice)
	}

	if targetDevice == "" {
		fmt.Println("[Sniffer] ERROR: No suitable device found!")
		wailsRuntime.EventsEmit(a.ctx, "sniffer_error", "Tidak ada device network yang cocok!")
		return
	}

	isSniffing = true
	fmt.Println("[Sniffer] Starting packet capture on:", targetDevice)
	wailsRuntime.EventsEmit(a.ctx, "sniffer_started", targetDevice)

	packetChan := make(chan sniffer.PacketInfo, 100) // Buffered channel
	go sniffer.StartSniffing(targetDevice, packetChan)

	go func() {
		for {
			select {
			case <-ctx.Done():
				isSniffing = false
				fmt.Println("[Sniffer] Stopped by context cancel")
				return
			case p := <-packetChan:
				wailsRuntime.EventsEmit(a.ctx, "new_packet", p)
			}
		}
	}()
}

func (a *App) StopSniffing() {
	if cancelSniff != nil {
		cancelSniff()
		cancelSniff = nil
		isSniffing = false
		wailsRuntime.EventsEmit(a.ctx, "sniff_stopped", "Sniffer terminated safely.")
	}
}