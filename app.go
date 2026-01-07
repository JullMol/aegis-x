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
var isSniffing bool

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

func (a *App) BlockIPAddress(ip string) string {
	if runtime.GOOS == "windows" {
		ruleName := fmt.Sprintf("AEGIS_BLOCK_%s", ip)

		cmdDirect := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=in", "action=block", "remoteip="+ip)
		errDirect := cmdDirect.Run()

		if errDirect == nil {
			exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
				"name="+ruleName+"_OUT", "dir=out", "action=block", "remoteip="+ip).Run()
			return "SUCCESS: IP " + ip + " blocked permanently."
		}

		psScript := fmt.Sprintf(`
			Start-Process -FilePath "netsh" -ArgumentList "advfirewall firewall add rule name=%s dir=in action=block remoteip=%s" -Verb RunAs -Wait
			Start-Process -FilePath "netsh" -ArgumentList "advfirewall firewall add rule name=%s_OUT dir=out action=block remoteip=%s" -Verb RunAs -Wait
		`, ruleName, ip, ruleName, ip)

		cmdPS := exec.Command("powershell", "-NoProfile", "-Command", psScript)
		errPS := cmdPS.Run()

		if errPS != nil {
			return "Failed: Click 'Yes' on UAC popup or run as Administrator."
		}
		return "SUCCESS: IP " + ip + " blocked via UAC elevation."
	} else {
		cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		err := cmd.Run()
		if err != nil {
			return "Error: Run application as root."
		}
		return "SUCCESS: IP " + ip + " blocked."
	}
}

func (a *App) StartLiveSniffing() {
	if isSniffing {
		return
	}

	var ctx context.Context
	ctx, cancelSniff = context.WithCancel(context.Background())

	devices, err := pcap.FindAllDevs()
	if err != nil || len(devices) == 0 {
		wailsRuntime.EventsEmit(a.ctx, "sniffer_error", "No network device found. Ensure Npcap is installed.")
		return
	}

	localIP, _, _, _ := scanner.GetLocalIP()
	var targetDevice string

	for _, d := range devices {
		for _, addr := range d.Addresses {
			if addr.IP.String() == localIP.String() {
				targetDevice = d.Name
				break
			}
		}
		if targetDevice != "" {
			break
		}
	}

	if targetDevice == "" {
		for _, d := range devices {
			if len(d.Addresses) > 0 && d.Addresses[0].IP.String() != "127.0.0.1" {
				targetDevice = d.Name
				break
			}
		}
	}

	if targetDevice == "" && len(devices) > 0 {
		targetDevice = devices[0].Name
	}

	if targetDevice == "" {
		wailsRuntime.EventsEmit(a.ctx, "sniffer_error", "No suitable network device found!")
		return
	}

	isSniffing = true
	wailsRuntime.EventsEmit(a.ctx, "sniffer_started", targetDevice)

	packetChan := make(chan sniffer.PacketInfo, 100)
	go sniffer.StartSniffing(targetDevice, packetChan)

	go func() {
		for {
			select {
			case <-ctx.Done():
				isSniffing = false
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