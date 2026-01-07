package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Device struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
}

type PortResult struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Service string `json:"service"`
}

func ScanPorts(ip string) []PortResult {
	ports := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB",
		3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy",
	}

	var results []PortResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	for port, service := range ports {
		wg.Add(1)
		go func(p int, s string) {
			defer wg.Done()
			address := net.JoinHostPort(ip, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", address, 1*time.Second)

			if err == nil {
				conn.Close()
				mu.Lock()
				results = append(results, PortResult{Port: p, Status: "Open", Service: s})
				mu.Unlock()
			}
		}(port, service)
	}

	wg.Wait()
	return results
}

func GetLocalIP() (net.IP, string, string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP, "internet", "internet", nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "", "", err
	}

	var fallbackIP net.IP
	var fallbackName string

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.To4() == nil || strings.HasPrefix(ip.String(), "169.254") {
				continue
			}

			ipStr := ip.String()

			if strings.HasPrefix(ipStr, "192.168.137.") {
				continue
			}

			if strings.HasPrefix(ipStr, "172.") {
				fallbackIP = ip
				fallbackName = iface.Name
				continue
			}

			if strings.HasPrefix(ipStr, "192.168.") || strings.HasPrefix(ipStr, "10.") {
				return ip, iface.Name, iface.Name, nil
			}

			if fallbackIP == nil {
				fallbackIP = ip
				fallbackName = iface.Name
			}
		}
	}

	if fallbackIP != nil {
		return fallbackIP, fallbackName, fallbackName, nil
	}

	return nil, "", "", fmt.Errorf("no active interface found")
}

func ScanRealNetwork() ([]Device, error) {
	localIP, _, _, err := GetLocalIP()
	if err != nil {
		return nil, err
	}

	ipParts := strings.Split(localIP.String(), ".")
	if len(ipParts) != 4 {
		return nil, fmt.Errorf("invalid IP format")
	}
	prefix := fmt.Sprintf("%s.%s.%s.", ipParts[0], ipParts[1], ipParts[2])

	var devices []Device
	var wg sync.WaitGroup
	var mu sync.Mutex

	devices = append(devices, Device{
		IP:       localIP.String(),
		Hostname: "This Device (You)",
		MAC:      "Local",
	})

	for i := 1; i < 255; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			targetIP := fmt.Sprintf("%s%d", prefix, id)

			if targetIP == localIP.String() {
				return
			}
			d := net.Dialer{Timeout: 500 * time.Millisecond}

			conn, err := d.Dial("tcp", targetIP+":80")

			if err == nil {
				conn.Close()
				mu.Lock()
				devices = append(devices, Device{
					IP:       targetIP,
					Hostname: "Active Host",
					MAC:      "Detected",
				})
				mu.Unlock()
			} else {
				uConn, uErr := net.DialTimeout("udp", targetIP+":12345", 200*time.Millisecond)
				if uErr == nil {
					uConn.Close()
				}
			}
		}(i)
	}

	wg.Wait()
	return devices, nil
}