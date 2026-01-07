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
    
    // NEW: Pause & Filter state untuk kontrol UI
    const [isPaused, setIsPaused] = useState(false);
    const [filter, setFilter] = useState("ALL");
    
    // NEW: Red Alert state
    const [showAlert, setShowAlert] = useState(false);
    const [alertData, setAlertData] = useState<any>(null);

    // NEW: Filtered packets untuk display
    const displayPackets = packets.filter(p => filter === "ALL" || p.protocol === filter);

    useEffect(() => {
        const unsub = EventsOn("new_packet", (p) => {
            // HANYA UPDATE JIKA TIDAK PAUSE
            if (!isPaused) {
                setPackets(prev => [p, ...prev].slice(0, 100));
            }
        });
        return () => unsub();
    }, [isPaused]); // Re-subscribe saat pause status berubah

    // Periodically enrich packets with Geo-IP data and analyze for threats
    useEffect(() => {
        if (packets.length > 0 && isSniffing && !isPaused) {
            const interval = setInterval(() => {
                // Kirim 30 paket terakhir untuk di-analisis
                const packetsToEnrich = packets.slice(0, 30);
                GetSecurityAnalysis([], packetsToEnrich).then(res => {
                    if (res && res.enriched_packets && res.enriched_packets.length > 0) {
                        // Merge enriched packets dengan existing packets
                        setPackets(prev => {
                            const enrichedMap = new Map(res.enriched_packets.map((p: any) => [p.timestamp + p.source + p.dest, p]));
                            return prev.map(p => enrichedMap.get(p.timestamp + p.source + p.dest) || p);
                        });
                    }
                    if (res && res.findings && res.findings.length > 0) {
                        // Filter duplicate findings
                        setAnalysis(prev => {
                            const newFindings = res.findings.filter((f: any) => 
                                !prev.some(existing => existing.summary === f.summary)
                            );
                            return [...prev, ...newFindings];
                        });
                    }
                }).catch(err => console.error("Periodic enrichment error:", err));
            }, 3000); // Interval 3 detik untuk deteksi cepat
            return () => clearInterval(interval);
        }
    }, [packets.length, isSniffing, isPaused]);

    // NEW: Trigger Red Alert ketika ada CREDENTIAL_LEAK
    useEffect(() => {
        const criticalHit = analysis.find(a => a.risk === "CRITICAL" && (a.type === "CREDENTIAL_LEAK" || a.summary?.includes("BOCOR")));
        if (criticalHit && !showAlert) {
            setAlertData(criticalHit);
            setShowAlert(true);
            
            // Mainkan suara alert
            try {
                const audio = new Audio('https://www.soundjay.com/buttons/beep-01a.mp3');
                audio.volume = 0.5;
                audio.play().catch(() => {});
            } catch {}
        }
    }, [analysis, showAlert]);

    function toggleSniff() {
        StartLiveSniffing();
        setIsSniffing(true);
    }

    function scan() {
        setLoading(true);
        console.log("Starting scan...");
        StartNetworkScan().then((foundDevices) => {
            console.log("Devices found:", foundDevices);
            setDevices(foundDevices);
            setLoading(false);
            
            if (foundDevices && foundDevices.length > 0) {
                StartLiveSniffing();
                setIsSniffing(true);
                console.log("Sniffer started, scanning ports on:", foundDevices[0].ip);
                
                ScanDevicePorts(foundDevices[0].ip).then(ports => {
                    console.log("Ports found:", ports);
                    if (ports && ports.length > 0) {
                        GetSecurityAnalysis(ports, packets).then(res => {
                            console.log("Analysis result:", res);
                            if (res && res.findings) {
                                setAnalysis(res.findings);
                            }
                            if (res && res.enriched_packets && res.enriched_packets.length > 0) {
                                setPackets(res.enriched_packets);
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
            if(ports && ports.length > 0) {
                GetSecurityAnalysis(ports, packets).then(res => {
                    if (res && res.findings) {
                        setAnalysis(res.findings);
                    }
                    if (res && res.enriched_packets && res.enriched_packets.length > 0) {
                        setPackets(res.enriched_packets);
                    }
                }).catch(err => console.error("Analysis error:", err));
            }
        }).catch(err => console.error("Port scan error:", err));
    }

    function handleBlock(ip: string) {
        BlockIPAddress(ip).then(result => {
            alert(result);
        }).catch(err => {
            alert("Error: " + err);
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

            {/* NEW: Control Panel - Filter & Pause */}
            <div style={{ 
                display: 'flex', 
                gap: '15px', 
                marginBottom: '20px', 
                padding: '15px', 
                background: '#111', 
                borderRadius: '8px', 
                border: '1px solid #222',
                alignItems: 'center'
            }}>
                <button 
                    onClick={() => setIsPaused(!isPaused)} 
                    style={{ 
                        background: isPaused ? '#ff4444' : '#333', 
                        color: '#fff',
                        border: isPaused ? '2px solid #ff6666' : '1px solid #444',
                        padding: '10px 20px',
                        borderRadius: '6px',
                        cursor: 'pointer',
                        fontWeight: 'bold',
                        fontSize: '14px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                    }}
                >
                    {isPaused ? "▶ RESUME" : "⏸ PAUSE"}
                </button>
                
                <select 
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)} 
                    style={{ 
                        background: '#222', 
                        color: '#00ff00', 
                        border: '1px solid #333',
                        padding: '10px 15px',
                        borderRadius: '6px',
                        cursor: 'pointer',
                        fontSize: '14px'
                    }}
                >
                    <option value="ALL">📡 ALL TRAFFIC</option>
                    <option value="TCP">🌐 TCP (HTTP/HTTPS)</option>
                    <option value="UDP">📢 UDP (DNS/Broadcast)</option>
                </select>
                
                <div style={{ marginLeft: 'auto', display: 'flex', gap: '20px', fontSize: '12px', color: '#888' }}>
                    <span>Total: <b style={{color: '#fff'}}>{packets.length}</b></span>
                    <span>Displayed: <b style={{color: '#00ff00'}}>{displayPackets.length}</b></span>
                    <span>Status: <b style={{color: isSniffing ? '#00ff00' : '#ff4444'}}>{isSniffing ? 'SNIFFING' : 'IDLE'}</b></span>
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
                        <div key={i} style={{ padding: '10px', borderLeft: `3px solid ${a.risk === 'CRITICAL' ? '#ff0000' : '#ff4444'}`, background: a.risk === 'CRITICAL' ? '#2a0a0a' : '#1a0a0a', marginBottom: '10px' }}>
                            <b style={{color: a.risk === 'CRITICAL' ? '#ff0000' : '#ff4444'}}>{a.risk} RISK{a.port ? `: Port ${a.port}` : ''}</b>
                            <p style={{fontSize: '12px', margin: '5px 0'}}>{a.summary}</p>
                            {a.detail && <p style={{fontSize: '11px', color: '#888'}}>{a.detail}</p>}
                        </div>
                    ))}
                </div>

                <div className="card" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                    <h3>REALTIME_TRAFFIC {isPaused && <span style={{color: '#ff4444', marginLeft: '10px'}}>⏸ PAUSED</span>}</h3>
                    <div style={{ maxHeight: '300px', overflowY: 'auto', fontSize: '12px' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr style={{ color: '#aaa', textAlign: 'left' }}>
                                    <th style={{ padding: '8px 0' }}>LOC</th>
                                    <th style={{ padding: '8px 0' }}>SOURCE</th>
                                    <th style={{ padding: '8px 0' }}>DEST</th>
                                    <th style={{ padding: '8px 0' }}>PROTO</th>
                                    <th style={{ padding: '8px 0' }}>ACTION</th>
                                </tr>
                            </thead>
                            <tbody>
                                {displayPackets.map((p, i) => (
                                    <tr key={i} style={{ 
                                        borderBottom: '1px solid #222', 
                                        borderLeft: p.payload && p.payload.match(/pass|user|login|token|auth/i) ? '4px solid #ff0000' : 'none',
                                        background: p.payload && p.payload.match(/pass|user|login|token|auth/i) ? 'rgba(255,0,0,0.1)' : 'transparent'
                                    }}>
                                        <td style={{ padding: '8px 0' }}>
                                            <span style={{ 
                                                background: p.location === 'LOCAL' ? '#1a3a1a' : p.location === 'MCAST' ? '#3a3a1a' : '#333', 
                                                padding: '2px 6px', 
                                                borderRadius: '4px', 
                                                fontSize: '10px', 
                                                color: p.location === 'LOCAL' ? '#00ff00' : p.location === 'MCAST' ? '#ffaa00' : '#fff' 
                                            }}>
                                                {p.location || '??'}
                                            </span>
                                        </td>
                                        <td style={{ color: '#ffaa00', padding: '8px 0' }}>{p.source}</td>
                                        <td style={{ padding: '8px 0' }}>{p.dest}</td>
                                        <td style={{ color: p.protocol === 'TCP' ? '#00ff00' : '#00ffff', padding: '8px 0' }}>{p.protocol}</td>
                                        <td style={{ padding: '8px 0' }}>
                                            <button 
                                                onClick={() => handleBlock(p.source)}
                                                style={{ 
                                                    background: 'none', 
                                                    color: '#ff4444', 
                                                    border: '1px solid #ff4444', 
                                                    cursor: 'pointer', 
                                                    fontSize: '10px', 
                                                    padding: '4px 8px', 
                                                    borderRadius: '4px',
                                                    transition: 'all 0.2s'
                                                }}
                                                onMouseOver={(e) => {
                                                    e.currentTarget.style.background = '#ff4444';
                                                    e.currentTarget.style.color = '#000';
                                                }}
                                                onMouseOut={(e) => {
                                                    e.currentTarget.style.background = 'none';
                                                    e.currentTarget.style.color = '#ff4444';
                                                }}
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

            {/* RED ALERT MODAL */}
            {showAlert && (
                <div style={{
                    position: 'fixed', 
                    top: 0, 
                    left: 0, 
                    width: '100%', 
                    height: '100%',
                    backgroundColor: 'rgba(180,0,0,0.95)', 
                    zIndex: 9999,
                    display: 'flex', 
                    flexDirection: 'column', 
                    justifyContent: 'center', 
                    alignItems: 'center',
                    animation: 'alertBlink 0.5s infinite alternate'
                }}>
                    <div style={{
                        background: '#1a0000',
                        padding: '60px 80px',
                        borderRadius: '20px',
                        border: '4px solid #ff0000',
                        textAlign: 'center',
                        boxShadow: '0 0 100px rgba(255,0,0,0.5)'
                    }}>
                        <h1 style={{ fontSize: '80px', color: '#fff', margin: 0, textShadow: '0 0 30px #ff0000' }}>⚠️ ALERT ⚠️</h1>
                        <h2 style={{ color: '#ff4444', fontSize: '28px', marginTop: '20px' }}>CREDENTIAL LEAK DETECTED!</h2>
                        <p style={{ color: '#ffaaaa', fontSize: '18px', marginTop: '15px' }}>{alertData?.summary}</p>
                        {alertData?.detail && <p style={{ color: '#ff8888', fontSize: '14px', marginTop: '10px' }}>{alertData.detail}</p>}
                        <button 
                            onClick={() => setShowAlert(false)}
                            style={{ 
                                padding: '20px 50px', 
                                fontSize: '18px', 
                                cursor: 'pointer', 
                                marginTop: '30px', 
                                border: 'none', 
                                borderRadius: '8px', 
                                fontWeight: 'bold',
                                background: '#00ff00',
                                color: '#000',
                                boxShadow: '0 0 20px rgba(0,255,0,0.5)'
                            }}
                        >
                            🔒 ACKNOWLEDGE & SECURE SYSTEM
                        </button>
                    </div>
                </div>
            )}

            <style>{`
                .card { background: #111; border: 1px solid #222; border-radius: 12px; padding: 20px; }
                .btn-primary { background: #00ff00; color: black; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; }
                .btn-secondary { background: transparent; color: #00ff00; border: 1px solid #00ff00; padding: 10px 20px; border-radius: 6px; cursor: pointer; }
                h3 { font-size: 12px; color: #555; margin-bottom: 15px; letter-spacing: 1px; }
                @keyframes alertBlink {
                    from { background-color: rgba(180,0,0,0.95); }
                    to { background-color: rgba(255,0,0,0.95); }
                }
            `}</style>
        </div>
    );
}

export default App;