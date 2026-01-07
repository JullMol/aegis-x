package sniffer

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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
	handle, err := pcap.OpenLive(deviceName, 65535, true, time.Second)
	if err != nil {
		return
	}
	defer handle.Close()

	handle.SetBPFFilter("ip")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		var srcIP, dstIP string

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		} else {
			ip6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ip6Layer == nil {
				continue
			}
			ip6, _ := ip6Layer.(*layers.IPv6)
			srcIP = ip6.SrcIP.String()
			dstIP = ip6.DstIP.String()
		}

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

		payload := ""
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload = string(appLayer.Payload())
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
			Location:  "",
		}
	}
}