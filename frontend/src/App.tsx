import { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { StartNetworkScan, ScanDevicePorts, GetSecurityAnalysis, StartLiveSniffing, BlockIPAddress } from "../wailsjs/go/main/App";
import { EventsOn } from "../wailsjs/runtime/runtime";

const COLORS = ['#00ff00', '#00ffff', '#ffbb28', '#ff4444'];

function App() {
    const [devices, setDevices] = useState<any[]>([]);
    const [packets, setPackets] = useState<any[]>([]);
    const [analysis, setAnalysis] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);
    const [isSniffing, setIsSniffing] = useState(false);
    const [targetIp, setTargetIp] = useState('');

    useEffect(() => {
        const unsub = EventsOn("new_packet", (p) => {
            setPackets(prev => [p, ...prev].slice(0, 50));
        });
        return () => unsub();
    }, []);

    function toggleSniff() {
        StartLiveSniffing();
        setIsSniffing(true);
    }

    function scan() {
        setLoading(true);
        console.log("Starting scan...");
        // 1. Jalankan Scan Network
        StartNetworkScan().then((foundDevices) => {
            console.log("Devices found:", foundDevices);
            setDevices(foundDevices);
            setLoading(false);
            
            // 2. Jika ketemu minimal 1 device (router), langsung jalankan protector & analisa
            if (foundDevices && foundDevices.length > 0) {
                StartLiveSniffing(); // Langsung jalankan sniffer otomatis
                setIsSniffing(true);
                console.log("Sniffer started, scanning ports on:", foundDevices[0].ip);
                
                // 3. Ambil IP pertama (biasanya router/gateway atau diri sendiri) untuk diinspeksi port-nya
                ScanDevicePorts(foundDevices[0].ip).then(ports => {
                    console.log("Ports found:", ports);
                    if (ports && ports.length > 0) {
                        GetSecurityAnalysis(ports, []).then(res => {
                            console.log("Analysis result:", res);
                            if (res && res.findings) {
                                setAnalysis(res.findings);
                            }
                        }).catch(err => console.error("Analysis error:", err));
                    } else {
                        console.log("No open ports found on target, but sniffer is running.");
                    }
                }).catch(err => console.error("Port scan error:", err));
            } else {
                console.log("No devices found, but you can still check traffic if sniffer runs.");
            }
        }).catch(err => {
            console.error("Scan error:", err);
            setLoading(false);
        });
    }

    function checkPorts(ip: string) {
        setTargetIp(ip);
        setAnalysis([]);
        
        ScanDevicePorts(ip).then(ports => {
            if(ports.length > 0) {
                GetSecurityAnalysis(ports, packets).then(res => {
                    setAnalysis(res.findings);
                    // Update packets with enriched data (location etc)
                    if (res.enriched_packets && res.enriched_packets.length > 0) {
                        setPackets(res.enriched_packets);
                    }
                });
            }
        });
    }

    const chartData = () => {
        const counts = packets.reduce((acc: any, p: any) => {
            acc[p.protocol] = (acc[p.protocol] || 0) + 1;
            return acc;
        }, {});
        return Object.keys(counts).map(name => ({ name, value: counts[name] }));
    };

    return (
        <div style={{ backgroundColor: '#050505', color: '#e0e0e0', minHeight: '100vh', padding: '20px', fontFamily: 'Inter, sans-serif' }}>
            {/* Header Area */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
                <h2 style={{ color: '#00ff00', letterSpacing: '2px' }}>AEGIS-X <span style={{color: '#444', fontSize: '14px'}}>v1.0.0</span></h2>
                <div style={{ display: 'flex', gap: '10px' }}>
                     <button 
                        onClick={scan} 
                        disabled={loading} 
                        className="btn-primary"
                        style={{ backgroundColor: loading ? '#333' : '#00ff00', color: loading ? '#888' : '#000' }}
                    >
                        {loading ? "INITIALIZING SHIELD..." : "ACTIVATE AEGIS SHIELD"}
                    </button>
                </div>
            </div>

            {/* Top Row: Score & Chart */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '20px', marginBottom: '20px' }}>
                <div className="card" style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                    <h3 style={{color: '#888'}}>SECURITY_SCORE</h3>
                    <h1 style={{ fontSize: '72px', color: analysis.length > 0 ? '#ff4444' : '#00ff00', margin: '10px 0' }}>
                        {analysis.length > 0 ? '65' : '100'}
                    </h1>
                    <p>{analysis.length > 0 ? '⚠️ Action Required' : '✅ System Shielded'}</p>
                </div>

                <div className="card" style={{ height: '250px' }}>
                    <h3>PROTOCOL_DISTRIBUTION</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie data={chartData()} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                                {chartData().map((_, index) => <Cell key={index} fill={COLORS[index % COLORS.length]} />)}
                            </Pie>
                            <Tooltip contentStyle={{backgroundColor: '#111', border: '1px solid #333'}} />
                            <Legend />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Bottom Row: Analysis & Logs */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                <div className="card">
                    <h3>THREAT_ADVISORY</h3>
                    {analysis.length === 0 && <p style={{color: '#666'}}>No threats detected in current session.</p>}
                    {analysis.map((a, i) => (
                        <div key={i} style={{ padding: '10px', borderLeft: '3px solid #ff4444', background: '#1a0a0a', marginBottom: '10px' }}>
                            <b style={{color: '#ff4444'}}>{a.risk} RISK: Port {a.port}</b>
                            <p style={{fontSize: '12px', margin: '5px 0'}}>{a.summary}</p>
                        </div>
                    ))}
                </div>

                <div className="card" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                    <h3>REALTIME_TRAFFIC</h3>
                    <div style={{ maxHeight: '300px', overflowY: 'auto', fontSize: '12px' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr style={{ color: '#aaa', textAlign: 'left' }}>
                                    <th style={{ padding: '8px 0' }}>TIME</th>
                                    <th style={{ padding: '8px 0' }}>SOURCE</th>
                                    <th style={{ padding: '8px 0' }}>DEST</th>
                                    <th style={{ padding: '8px 0' }}>PROTO</th>
                                    <th style={{ padding: '8px 0' }}>ACTION</th>
                                </tr>
                            </thead>
                            <tbody>
                                {packets.map((p, i) => (
                                    <tr key={i} style={{ borderBottom: '1px solid #222', borderLeft: p.payload && p.payload.match(/pass|user|login|token|auth/i) ? '4px solid #ff4444' : 'none' }}>
                                        <td style={{ padding: '8px 0', color: '#888' }}>{p.timestamp}</td>
                                        <td style={{ color: '#ffaa00', padding: '8px 0' }}>
                                            <span style={{ background: '#333', padding: '2px 5px', borderRadius: '4px', marginRight: '5px', fontSize: '10px', color: '#fff' }}>
                                                {p.location || '??'}
                                            </span>
                                            {p.source}
                                        </td>
                                        <td style={{ padding: '8px 0' }}>{p.dest}</td>
                                        <td style={{ color: p.protocol === 'TCP' ? '#00ff00' : '#00ffff', padding: '8px 0' }}>{p.protocol}</td>
                                        <td style={{ padding: '8px 0' }}>
                                            <button 
                                                onClick={() => BlockIPAddress(p.source)}
                                                style={{ background: 'none', color: '#ff4444', border: '1px solid #ff4444', cursor: 'pointer', fontSize: '10px', padding: '4px 8px', borderRadius: '4px' }}
                                            >
                                                KILL
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <style>{`
                .card { background: #111; border: 1px solid #222; border-radius: 12px; padding: 20px; }
                .btn-primary { background: #00ff00; color: black; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; }
                .btn-secondary { background: transparent; color: #00ff00; border: 1px solid #00ff00; padding: 10px 20px; border-radius: 6px; cursor: pointer; }
                h3 { font-size: 12px; color: #555; margin-bottom: 15px; letter-spacing: 1px; }
            `}</style>
        </div>
    );
}

export default App;