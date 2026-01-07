import sys
import json
import re
import urllib.request

def get_location(ip):
    try:
        first_octet = int(ip.split('.')[0])
        if first_octet >= 224:
            return "MCAST"
        if ip.startswith("169.254."):
            return "LINK"
    except:
        pass
    
    if ip.startswith(("192.", "10.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
        return "LOCAL"
    
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=0.3) as response:
            data = json.loads(response.read().decode())
            return data.get("countryCode", "??")
    except:
        return "??"

def analyze_all(ports_json, packets_json):
    ports = json.loads(ports_json)
    packets = json.loads(packets_json)
    findings = []
    seen_warnings = set()
    
    for p in ports:
        if p['port'] == 80:
            findings.append({
                "port": 80,
                "risk": "HIGH",
                "summary": "Insecure HTTP on port 80 detected.",
                "action": "Disable HTTP or force HTTPS redirection."
            })
        elif p['port'] == 53:
            findings.append({
                "port": 53,
                "risk": "INFO",
                "summary": "DNS Service Detected.",
                "action": "Ensure DNSSEC is active."
            })
    
    http_destinations = set()
    https_destinations = set()
    external_connections = set()
    
    for pkt in packets:
        dest_ip = pkt.get('dest', '')
        protocol = pkt.get('protocol', '')
        payload = pkt.get('payload', '')
        dst_port = pkt.get('dst_port', 0)
        src_port = pkt.get('src_port', 0)
        
        pkt['location'] = get_location(dest_ip)
        
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
                        "summary": f"⚠️ Unencrypted HTTP traffic to {dest_ip}",
                        "detail": f"Port 80 is NOT encrypted.",
                        "action": "Use HTTPS instead."
                    })
        
        if protocol == 'TCP' and (dst_port == 443 or src_port == 443):
            if dest_ip not in https_destinations:
                https_destinations.add(dest_ip)
                warning_key = f"https_{dest_ip}"
                if warning_key not in seen_warnings and len(https_destinations) == 1:
                    seen_warnings.add(warning_key)
                    findings.append({
                        "port": 443,
                        "risk": "INFO",
                        "type": "HTTPS_TRAFFIC",
                        "summary": f"🔒 Encrypted HTTPS connection to {dest_ip}",
                        "detail": f"Traffic to {pkt['location']} via TLS.",
                        "action": "Connection secure."
                    })
        
        if not dest_ip.startswith(('192.168.', '10.', '172.', '127.', '224.', '239.', '169.254.', '')):
            if dest_ip not in external_connections:
                external_connections.add(dest_ip)
        
        if re.search(r"(pass|user|login|token|auth)=", payload, re.I):
            warning_key = f"cred_{dest_ip}"
            if warning_key not in seen_warnings:
                seen_warnings.add(warning_key)
                findings.append({
                    "port": 0,
                    "risk": "CRITICAL",
                    "type": "CREDENTIAL_LEAK",
                    "summary": f"🚨 CREDENTIAL LEAK to {dest_ip}!",
                    "detail": f"Target: {dest_ip} | Location: {pkt['location']}",
                    "action": "Kill connection and reset passwords."
                })
    
    if len(external_connections) >= 1 and "external_summary" not in seen_warnings:
        seen_warnings.add("external_summary")
        findings.append({
            "port": 0,
            "risk": "MEDIUM",
            "type": "NETWORK_ACTIVITY",
            "summary": f"📡 {len(external_connections)} external connection(s) detected",
            "detail": f"IPs: {', '.join(list(external_connections)[:3])}",
            "action": "Monitor network activity."
        })

    return json.dumps({"findings": findings, "enriched_packets": packets})

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print(analyze_all(sys.argv[1], sys.argv[2]))