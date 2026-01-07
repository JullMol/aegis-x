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
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Menambahkan rule baru di Windows Firewall
		ruleName := fmt.Sprintf("AEGIS_BLOCK_%s", ip)
		args := []string{"advfirewall", "firewall", "add", "rule", 
			"name=" + ruleName, "dir=in", "action=block", "remoteip=" + ip}
		cmd = exec.Command("netsh", args...)
	} else {
		// Untuk Linux (iptables)
		cmd = exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	}

	err := cmd.Run()
	if err != nil {
		return "Error: Jalankan aplikasi sebagai Administrator/Root"
	}
	return "SUCCESS: IP " + ip + " telah diblokir secara permanen."
}

// Global variable to track sniffer status
var isSniffing bool

func (a *App) StartLiveSniffing() {
	// Jika sniffer sudah berjalan, abaikan
	if isSniffing {
		return
	}

	// Buat context baru yang bisa di-cancel
	var ctx context.Context
	ctx, cancelSniff = context.WithCancel(context.Background())

	// Ambil semua device yang dikenali oleh Npcap
	devices, err := pcap.FindAllDevs()
	if err != nil || len(devices) == 0 {
		fmt.Println("Gagal menemukan device pcap")
		return
	}

	localIP, _, _, _ := scanner.GetLocalIP()
	var targetDevice string

	// Cari device pcap yang memiliki IP yang sama dengan IP lokal kita
	for _, d := range devices {
		for _, addr := range d.Addresses {
			if addr.IP.String() == localIP.String() {
				targetDevice = d.Name
				break
			}
		}
	}

	if targetDevice == "" {
		fmt.Println("Device pcap untuk IP ini tidak ditemukan")
		return
	}

	isSniffing = true // Set status running
	packetChan := make(chan sniffer.PacketInfo)
	go sniffer.StartSniffing(targetDevice, packetChan)

	go func() {
		// remove defer close(packetChan) to avoid panic on write
		for {
			select {
			case <-ctx.Done():
				isSniffing = false // Reset status when stopped
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