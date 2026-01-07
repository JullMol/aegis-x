import sys
import json
import re
import urllib.request

def get_location(ip):
    # Filter IP lokal (192.168.x.x, 10.x.x.x, 127.0.x.x)
    if ip.startswith(("192.", "10.", "127.", "172.16.")):
        return "LOCAL"
    try:
        # Menggunakan API gratis ip-api.com
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=1) as response:
            data = json.loads(response.read().decode())
            return data.get("countryCode", "??")
    except:
        return "??"

def analyze_all(ports_json, packets_json):
    ports = json.loads(ports_json)
    packets = json.loads(packets_json)
    findings = []
    
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
    
    # Tambahkan info lokasi ke setiap paket
    for pkt in packets:
        pkt['location'] = get_location(pkt['dest'])
        
        # Cek Credential Leak (Fitur 2)
        payload = pkt.get('payload', '')
        if re.search(r"(pass|user|login|token|auth)=", payload, re.I):
            findings.append({
                "port": 0,
                "risk": "CRITICAL", 
                "summary": f"BOCOR! Data sensitif terdeteksi ke {pkt['dest']} ({pkt['location']})",
                "action": "IMMEDIATE ACTION: Kill connection and reset passwords."
            })

    return json.dumps({"findings": findings, "enriched_packets": packets})

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print(analyze_all(sys.argv[1], sys.argv[2]))