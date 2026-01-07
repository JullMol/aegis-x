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
		// Ambil layer Network (IP) - support both IPv4 and IPv6
		var srcIP, dstIP string
		
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		} else {
			// Try IPv6
			ip6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ip6Layer == nil {
				continue // Skip if neither IPv4 nor IPv6
			}
			ip6, _ := ip6Layer.(*layers.IPv6)
			srcIP = ip6.SrcIP.String()
			dstIP = ip6.DstIP.String()
		}

		// Ambil info protokol transport
		proto := "OTHER"
		if packet.Layer(layers.LayerTypeTCP) != nil {
			proto = "TCP"
		} else if packet.Layer(layers.LayerTypeUDP) != nil {
			proto = "UDP"
		} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
			proto = "ICMP"
		} else if packet.Layer(layers.LayerTypeICMPv6) != nil {
			proto = "ICMPv6"
		}

		// Ambil payload (Application Layer)
		payload := ""
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload = string(appLayer.Payload())
		}

		// Kirim data ke channel
		packetChan <- PacketInfo{
			Timestamp: time.Now().Format("15:04:05.000"),
			Source:    srcIP,
			Dest:      dstIP,
			Protocol:  proto,
			Length:    packet.Metadata().Length,
			Info:      fmt.Sprintf("%s -> %s", srcIP, dstIP),
			Payload:   payload,
			Location:  "", // Will be enriched by Python analyzer
		}
	}
}