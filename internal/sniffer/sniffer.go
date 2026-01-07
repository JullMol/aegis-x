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
	SrcPort   int    `json:"src_port"`
	Dest      string `json:"dest"`
	DstPort   int    `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Length    int    `json:"length"`
	Info      string `json:"info"`
	Payload   string `json:"payload"`
	Location  string `json:"location"`
}

func StartSniffing(deviceName string, packetChan chan PacketInfo) {
	fmt.Println("[Sniffer] Opening device:", deviceName)

	// Membuka device untuk sniffing
	// 65535 adalah snaplen max, true adalah promiscuous mode
	// Timeout 1 second - tidak terlalu lama tapi cukup untuk buffer
	handle, err := pcap.OpenLive(deviceName, 65535, true, time.Second)
	if err != nil {
		fmt.Printf("[Sniffer] ERROR: Gagal membuka device: %v\n", err)
		return
	}
	defer handle.Close()

	fmt.Println("[Sniffer] Device opened successfully!")
	fmt.Println("[Sniffer] Link type:", handle.LinkType())

	// BPF Filter: Hanya TCP dan UDP (skip ICMP noise)
	// Uncomment jika ingin filter
	err = handle.SetBPFFilter("ip")
	if err != nil {
		fmt.Printf("[Sniffer] Warning: BPF filter failed: %v\n", err)
	} else {
		fmt.Println("[Sniffer] BPF filter 'ip' applied successfully")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packetCount := 0
	fmt.Println("[Sniffer] Starting packet capture loop...")
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

		// Ambil info protokol transport dan port
		proto := "OTHER"
		var srcPort, dstPort int

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			proto = "TCP"
			tcp, _ := tcpLayer.(*layers.TCP)
			srcPort = int(tcp.SrcPort)
			dstPort = int(tcp.DstPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			proto = "UDP"
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = int(udp.SrcPort)
			dstPort = int(udp.DstPort)
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
		packetCount++
		if packetCount <= 5 || packetCount%50 == 0 {
			fmt.Printf("[Sniffer] Packet #%d: %s -> %s (%s)\n", packetCount, srcIP, dstIP, proto)
		}
		
		packetChan <- PacketInfo{
			Timestamp: time.Now().Format("15:04:05.000"),
			Source:    srcIP,
			SrcPort:   srcPort,
			Dest:      dstIP,
			DstPort:   dstPort,
			Protocol:  proto,
			Length:    packet.Metadata().Length,
			Info:      fmt.Sprintf("%s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort),
			Payload:   payload,
			Location:  "", // Will be enriched by Python analyzer
		}
	}
}