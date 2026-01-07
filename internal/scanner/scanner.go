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
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "", "", err
	}

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

			return ip, iface.Name, iface.Name, nil
		}
	}
	return nil, "", "", fmt.Errorf("tidak ada interface aktif")
}

func ScanRealNetwork() ([]Device, error) {
	localIP, _, _, err := GetLocalIP()
	if err != nil {
		return nil, err
	}

	ipParts := strings.Split(localIP.String(), ".")
	if len(ipParts) != 4 {
		return nil, fmt.Errorf("format IP tidak valid")
	}
	prefix := fmt.Sprintf("%s.%s.%s.", ipParts[0], ipParts[1], ipParts[2])

	fmt.Printf("Mulai Scanning pada IP: %s\n", localIP.String())

	var devices []Device
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Selalu tambahkan device lokal kita sendiri untuk demo purposes
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
				return // Skip, sudah ditambahkan di atas
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
	fmt.Printf("Scan selesai. Ditemukan %d perangkat aktif.\n", len(devices))
	return devices, nil
}