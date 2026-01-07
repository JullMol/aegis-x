import sys
sys.path.insert(0, 'scripts')
from analyzer import analyze_all

# Test case: Empty ports, one packet with credential leak
ports_json = "[]"
packets_json = '[{"dest":"8.8.8.8","source":"192.168.1.1","payload":"username=test&password=secret"}]'

result = analyze_all(ports_json, packets_json)
print("Result:", result)
