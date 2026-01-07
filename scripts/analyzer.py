import sys
import json
import re
import urllib.request

def get_location(ip):
    # FILTER KETAT: Multicast (224-239), Link-local, dan IP Lokal
    # Ini WAJIB agar tidak macet/timeout saat lookup
    try:
        first_octet = int(ip.split('.')[0])
        # Multicast range: 224.0.0.0 - 239.255.255.255
        if first_octet >= 224:
            return "MCAST"
        # Link-local: 169.254.x.x
        if ip.startswith("169.254."):
            return "LINK"
    except:
        pass
    
    # Filter IP lokal (Private networks)
    if ip.startswith(("192.", "10.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
        return "LOCAL"
    
    try:
        # Timeout 0.2 detik - KRUSIAL agar UI tidak lag
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=0.2) as response:
            data = json.loads(response.read().decode())
            return data.get("countryCode", "??")
    except:
        return "??"

def analyze_all(ports_json, packets_json):
    ports = json.loads(ports_json)
    packets = json.loads(packets_json)
    findings = []
    seen_warnings = set()  # Avoid duplicate warnings
    
    # 1. Analisa Port (Fitur Lama)
    for p in ports:
        if p['port'] == 80:
             findings.append({
                "port": 80,
                "risk": "HIGH",
                "summary": "Insecure HTTP on port 80 detected. Potential for data interception.",
                "action": "Disable HTTP or force HTTPS redirection."
            })
        elif p['port'] == 53:
             findings.append({
                "port": 53,
                "risk": "INFO",
                "summary": "DNS Service Detected.",
                "action": "Ensure DNSSEC is active."
            })
    
    # 2. Analisa Traffic - DETEKSI DARI PAKET LANGSUNG
    http_destinations = set()
    https_destinations = set()
    external_connections = set()
    
    for pkt in packets:
        dest_ip = pkt.get('dest', '')
        src_ip = pkt.get('source', '')
        protocol = pkt.get('protocol', '')
        payload = pkt.get('payload', '')
        dst_port = pkt.get('dst_port', 0)
        src_port = pkt.get('src_port', 0)
        
        # Enrichment: Add location
        pkt['location'] = get_location(dest_ip)
        
        # DETEKSI HTTP BERDASARKAN PORT 80 (PALING PENTING!)
        if protocol == 'TCP' and (dst_port == 80 or src_port == 80):
            if dest_ip not in http_destinations:
                http_destinations.add(dest_ip)
                warning_key = f"http_{dest_ip}"
                if warning_key not in seen_warnings:
                    seen_warnings.add(warning_key)
                    findings.append({
                        "port": 80,
                        "risk": "HIGH",
                        "type": "HTTP_TRAFFIC",
                        "summary": f"⚠️ Unencrypted HTTP traffic detected to {dest_ip}",
                        "detail": f"Port 80 traffic is NOT encrypted. Data can be intercepted.",
                        "action": "Use HTTPS (port 443) instead of HTTP (port 80)."
                    })
        
        # Track HTTPS connections (port 443) - informational
        if protocol == 'TCP' and (dst_port == 443 or src_port == 443):
            https_destinations.add(dest_ip)
        
        # Detect ALL external connections (public IPs)
        if not dest_ip.startswith(('192.168.', '10.', '172.', '127.', '224.', '239.', '169.254.')):
            if dest_ip and dest_ip not in external_connections:
                external_connections.add(dest_ip)
        
        # Cek Credential Leak (Fitur 2)
        if re.search(r"(pass|user|login|token|auth)=", payload, re.I):
            warning_key = f"cred_{dest_ip}"
            if warning_key not in seen_warnings:
                seen_warnings.add(warning_key)
                findings.append({
                    "port": 0,
                    "risk": "CRITICAL",
                    "type": "CREDENTIAL_LEAK",
                    "summary": f"🚨 BOCOR! Data sensitif terdeteksi ke {dest_ip} ({pkt['location']})",
                    "detail": f"Target: {dest_ip} | Protocol: {protocol} | Location: {pkt['location']}",
                    "action": "IMMEDIATE ACTION: Kill connection and reset passwords."
                })
    
    # 3. Summary warning jika ada banyak koneksi eksternal
    if len(external_connections) > 3 and "external_summary" not in seen_warnings:
        seen_warnings.add("external_summary")
        findings.append({
            "port": 0,
            "risk": "MEDIUM",
            "type": "NETWORK_ACTIVITY",
            "summary": f"📡 High network activity: {len(external_connections)} external connections detected",
            "detail": f"IPs: {', '.join(list(external_connections)[:5])}...",
            "action": "Review if all connections are legitimate."
        })

    return json.dumps({"findings": findings, "enriched_packets": packets})

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print(analyze_all(sys.argv[1], sys.argv[2]))