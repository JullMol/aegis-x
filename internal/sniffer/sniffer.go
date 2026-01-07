package sniffer

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketInfo adalah struktur data yang dikirim ke UI
type PacketInfo struct {
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Dest      string `json:"dest"`
	Protocol  string `json:"protocol"`
	Length    int    `json:"length"`
	Info      string `json:"info"`
	Payload   string `json:"payload"`
	Location  string `json:"location"`
}

func StartSniffing(deviceName string, packetChan chan PacketInfo) {
	// Memuka device untuk sniffing
	// 1600 adalah snaplen (ukuran paket), true adalah promiscuous mode
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Gagal membuka device: %v\n", err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for packet := range packetSource.Packets() {
		// Ambil layer Network (IP)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		// Ambil info protokol transport
		proto := "OTHER"
		if packet.Layer(layers.LayerTypeTCP) != nil {
			proto = "TCP"
		} else if packet.Layer(layers.LayerTypeUDP) != nil {
			proto = "UDP"
		} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
			proto = "ICMP"
		}

		// Ambil payload (Application Layer)
		// opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		payload := ""
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload = string(appLayer.Payload())
		}
		// If payload is empty but we want to see something for testing, maybe just use hex dump or skip?
		// For now let's keep it simple.

		// Kirim data ke channel
		packetChan <- PacketInfo{
			Timestamp: time.Now().Format("15:04:05.000"),
			Source:    ip.SrcIP.String(),
			Dest:      ip.DstIP.String(),
			Protocol:  proto,
			Length:    packet.Metadata().Length,
			Info:      fmt.Sprintf("%s -> %s", ip.SrcIP, ip.DstIP),
			Payload:   payload,
		}
	}
}