import { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { StartNetworkScan, ScanDevicePorts, GetSecurityAnalysis, StartLiveSniffing, BlockIPAddress } from "../wailsjs/go/main/App";
import { EventsOn } from "../wailsjs/runtime/runtime";

const PROTOCOL_COLORS: Record<string, string> = {
    TCP: '#00ff88',
    UDP: '#00d4ff',
    ICMP: '#ffaa00',
    ICMPv6: '#ff6b6b',
    OTHER: '#888888'
};

const RISK_STYLES: Record<string, { bg: string; border: string; text: string }> = {
    CRITICAL: { bg: 'rgba(255, 51, 102, 0.15)', border: '#ff3366', text: '#ff3366' },
    HIGH: { bg: 'rgba(255, 170, 0, 0.15)', border: '#ffaa00', text: '#ffaa00' },
    MEDIUM: { bg: 'rgba(0, 212, 255, 0.15)', border: '#00d4ff', text: '#00d4ff' },
    INFO: { bg: 'rgba(255, 255, 255, 0.05)', border: '#666', text: '#888' }
};

function App() {
    const [packets, setPackets] = useState<any[]>([]);
    const [analysis, setAnalysis] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);
    const [isSniffing, setIsSniffing] = useState(false);
    const [isPaused, setIsPaused] = useState(false);
    const [filter, setFilter] = useState("ALL");
    const [showAlert, setShowAlert] = useState(false);
    const [alertData, setAlertData] = useState<any>(null);

    const displayPackets = packets.filter(p => filter === "ALL" || p.protocol === filter);
    const securityScore = analysis.length > 0 ? Math.max(0, 100 - (analysis.length * 15)) : 100;

    useEffect(() => {
        const unsub = EventsOn("new_packet", (p) => {
            if (!isPaused) {
                setPackets(prev => [p, ...prev].slice(0, 100));
            }
        });
        return () => unsub();
    }, [isPaused]);

    useEffect(() => {
        if (packets.length > 0 && isSniffing && !isPaused) {
            const interval = setInterval(() => {
                const packetsToEnrich = packets.slice(0, 30);
                GetSecurityAnalysis([], packetsToEnrich).then(res => {
                    if (res?.enriched_packets?.length > 0) {
                        setPackets(prev => {
                            const enrichedMap = new Map(res.enriched_packets.map((p: any) => [p.timestamp + p.source + p.dest, p]));
                            return prev.map(p => enrichedMap.get(p.timestamp + p.source + p.dest) || p);
                        });
                    }
                    if (res?.findings?.length > 0) {
                        setAnalysis(prev => {
                            const newFindings = res.findings.filter((f: any) => !prev.some(existing => existing.summary === f.summary));
                            return [...prev, ...newFindings];
                        });
                    }
                }).catch(() => {});
            }, 3000);
            return () => clearInterval(interval);
        }
    }, [packets.length, isSniffing, isPaused]);

    useEffect(() => {
        const criticalHit = analysis.find(a => a.risk === "CRITICAL" && a.type === "CREDENTIAL_LEAK");
        if (criticalHit && !showAlert) {
            setAlertData(criticalHit);
            setShowAlert(true);
        }
    }, [analysis, showAlert]);

    function handleActivate() {
        setLoading(true);
        setAnalysis([]);
        StartNetworkScan().then((devices) => {
            setLoading(false);
            if (devices?.length > 0) {
                StartLiveSniffing();
                setIsSniffing(true);
                ScanDevicePorts(devices[0].ip).then(ports => {
                    if (ports?.length > 0) {
                        GetSecurityAnalysis(ports, packets).then(res => {
                            if (res?.findings) setAnalysis(res.findings);
                        });
                    }
                });
            }
        }).catch(() => setLoading(false));
    }

    function handleBlock(ip: string) {
        BlockIPAddress(ip).then(result => alert(result));
    }

    const chartData = () => {
        const counts = packets.reduce((acc: any, p: any) => {
            acc[p.protocol] = (acc[p.protocol] || 0) + 1;
            return acc;
        }, {});
        return Object.keys(counts).map(name => ({ name, value: counts[name], color: PROTOCOL_COLORS[name] || '#888' }));
    };

    const getScoreColor = () => {
        if (securityScore >= 80) return '#00ff88';
        if (securityScore >= 50) return '#ffaa00';
        return '#ff3366';
    };

    return (
        <div style={styles.container}>
            <header style={styles.header}>
                <div style={styles.logoSection}>
                    <h1 style={styles.logo}>AEGIS-X</h1>
                    <span style={styles.version}>v1.0.0</span>
                    <div style={{ ...styles.statusDot, background: isSniffing ? '#00ff88' : '#666' }} />
                    <span style={{ ...styles.statusText, color: isSniffing ? '#00ff88' : '#666' }}>
                        {isSniffing ? 'LIVE' : 'IDLE'}
                    </span>
                </div>
                <button onClick={handleActivate} disabled={loading} style={styles.activateBtn}>
                    {loading ? 'INITIALIZING...' : 'ACTIVATE SHIELD'}
                </button>
            </header>

            <div style={styles.controlBar}>
                <button onClick={() => setIsPaused(!isPaused)} style={{ ...styles.controlBtn, background: isPaused ? '#ff3366' : 'transparent', borderColor: isPaused ? '#ff3366' : '#333' }}>
                    {isPaused ? '▶ RESUME' : '⏸ PAUSE'}
                </button>
                <select value={filter} onChange={(e) => setFilter(e.target.value)} style={styles.filterSelect}>
                    <option value="ALL">ALL TRAFFIC</option>
                    <option value="TCP">TCP ONLY</option>
                    <option value="UDP">UDP ONLY</option>
                </select>
                <div style={styles.statsBar}>
                    <span>Total: <b style={{ color: '#fff' }}>{packets.length}</b></span>
                    <span>Displayed: <b style={{ color: '#00ff88' }}>{displayPackets.length}</b></span>
                    <span>Threats: <b style={{ color: analysis.length > 0 ? '#ff3366' : '#00ff88' }}>{analysis.length}</b></span>
                </div>
            </div>

            <div style={styles.mainGrid}>
                <div style={styles.card}>
                    <h3 style={styles.cardTitle}>SECURITY SCORE</h3>
                    <div style={styles.scoreContainer}>
                        <div style={{ ...styles.scoreCircle, borderColor: getScoreColor(), boxShadow: `0 0 40px ${getScoreColor()}40` }}>
                            <span style={{ ...styles.scoreNumber, color: getScoreColor() }}>{securityScore}</span>
                        </div>
                        <p style={{ color: getScoreColor(), marginTop: '16px', fontWeight: 500 }}>
                            {securityScore >= 80 ? '✓ System Protected' : securityScore >= 50 ? '⚠ Action Required' : '✕ Critical Threats'}
                        </p>
                    </div>
                </div>

                <div style={styles.card}>
                    <h3 style={styles.cardTitle}>PROTOCOL DISTRIBUTION</h3>
                    <ResponsiveContainer width="100%" height={180}>
                        <PieChart>
                            <Pie data={chartData()} innerRadius={50} outerRadius={70} paddingAngle={3} dataKey="value">
                                {chartData().map((entry, index) => <Cell key={index} fill={entry.color} />)}
                            </Pie>
                            <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: '8px' }} />
                        </PieChart>
                    </ResponsiveContainer>
                    <div style={styles.legendContainer}>
                        {chartData().map((entry, i) => (
                            <div key={i} style={styles.legendItem}>
                                <div style={{ ...styles.legendDot, background: entry.color }} />
                                <span>{entry.name}: {entry.value}</span>
                            </div>
                        ))}
                    </div>
                </div>

                <div style={styles.card}>
                    <h3 style={styles.cardTitle}>THREAT ADVISORY</h3>
                    <div style={styles.threatList}>
                        {analysis.length === 0 && <p style={{ color: '#666', textAlign: 'center', padding: '20px' }}>No threats detected</p>}
                        {analysis.map((a, i) => {
                            const style = RISK_STYLES[a.risk] || RISK_STYLES.INFO;
                            return (
                                <div key={i} style={{ ...styles.threatItem, background: style.bg, borderLeftColor: style.border }}>
                                    <span style={{ ...styles.riskBadge, background: style.border }}>{a.risk}</span>
                                    <p style={{ margin: '8px 0 4px', fontWeight: 500 }}>{a.summary}</p>
                                    {a.detail && <p style={{ fontSize: '12px', color: '#888' }}>{a.detail}</p>}
                                </div>
                            );
                        })}
                    </div>
                </div>

                <div style={styles.card}>
                    <h3 style={styles.cardTitle}>
                        REALTIME TRAFFIC
                        {isPaused && <span style={{ color: '#ff3366', marginLeft: '10px', fontSize: '10px' }}>⏸ PAUSED</span>}
                    </h3>
                    <div style={styles.tableContainer}>
                        <table style={styles.table}>
                            <thead>
                                <tr>
                                    <th style={styles.th}>LOC</th>
                                    <th style={styles.th}>SOURCE</th>
                                    <th style={styles.th}>DESTINATION</th>
                                    <th style={styles.th}>PROTO</th>
                                    <th style={styles.th}>ACTION</th>
                                </tr>
                            </thead>
                            <tbody>
                                {displayPackets.slice(0, 50).map((p, i) => (
                                    <tr key={i} style={styles.tr}>
                                        <td style={styles.td}>
                                            <span style={styles.locBadge}>{p.location || '??'}</span>
                                        </td>
                                        <td style={{ ...styles.td, color: '#ffaa00' }}>{p.source}:{p.src_port || ''}</td>
                                        <td style={styles.td}>{p.dest}:{p.dst_port || ''}</td>
                                        <td style={{ ...styles.td, color: PROTOCOL_COLORS[p.protocol] }}>{p.protocol}</td>
                                        <td style={styles.td}>
                                            <button onClick={() => handleBlock(p.source)} style={styles.killBtn}>KILL</button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {showAlert && (
                <div style={styles.alertOverlay}>
                    <div style={styles.alertBox}>
                        <h1 style={styles.alertTitle}>⚠️ CREDENTIAL LEAK DETECTED</h1>
                        <p style={styles.alertMessage}>{alertData?.summary}</p>
                        {alertData?.detail && <p style={styles.alertDetail}>{alertData.detail}</p>}
                        <button onClick={() => setShowAlert(false)} style={styles.alertButton}>ACKNOWLEDGE & SECURE</button>
                    </div>
                </div>
            )}
        </div>
    );
}

const styles: Record<string, React.CSSProperties> = {
    container: { background: '#0a0a0f', minHeight: '100vh', padding: '20px', fontFamily: 'Inter, sans-serif' },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', padding: '0 10px' },
    logoSection: { display: 'flex', alignItems: 'center', gap: '12px' },
    logo: { fontSize: '24px', fontWeight: 700, color: '#00ff88', letterSpacing: '3px', margin: 0 },
    version: { fontSize: '11px', color: '#666', background: '#1a1a2e', padding: '4px 8px', borderRadius: '4px' },
    statusDot: { width: '8px', height: '8px', borderRadius: '50%', animation: 'pulse 2s infinite' },
    statusText: { fontSize: '11px', fontWeight: 600, letterSpacing: '1px' },
    activateBtn: { background: 'linear-gradient(135deg, #00ff88 0%, #00cc6a 100%)', color: '#000', border: 'none', padding: '12px 28px', borderRadius: '8px', fontWeight: 600, fontSize: '13px', cursor: 'pointer', letterSpacing: '1px', boxShadow: '0 4px 20px rgba(0, 255, 136, 0.3)' },
    controlBar: { display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '20px', padding: '12px 16px', background: 'rgba(20, 20, 30, 0.6)', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.05)' },
    controlBtn: { border: '1px solid #333', color: '#fff', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: 500, fontSize: '12px' },
    filterSelect: { background: '#1a1a2e', color: '#00ff88', border: '1px solid #333', padding: '8px 12px', borderRadius: '6px', cursor: 'pointer' },
    statsBar: { marginLeft: 'auto', display: 'flex', gap: '20px', fontSize: '12px', color: '#888' },
    mainGrid: { display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px' },
    card: { background: 'rgba(20, 20, 30, 0.8)', backdropFilter: 'blur(10px)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '12px', padding: '20px', minHeight: '200px' },
    cardTitle: { fontSize: '11px', color: '#666', letterSpacing: '2px', marginBottom: '16px', fontWeight: 600 },
    scoreContainer: { display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 'calc(100% - 40px)' },
    scoreCircle: { width: '120px', height: '120px', borderRadius: '50%', border: '4px solid', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.3)' },
    scoreNumber: { fontSize: '48px', fontWeight: 700 },
    legendContainer: { display: 'flex', justifyContent: 'center', gap: '16px', flexWrap: 'wrap' },
    legendItem: { display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#888' },
    legendDot: { width: '8px', height: '8px', borderRadius: '50%' },
    threatList: { maxHeight: '200px', overflowY: 'auto' },
    threatItem: { padding: '12px', borderLeft: '3px solid', marginBottom: '8px', borderRadius: '0 8px 8px 0' },
    riskBadge: { fontSize: '10px', padding: '2px 8px', borderRadius: '4px', color: '#fff', fontWeight: 600 },
    tableContainer: { maxHeight: '200px', overflowY: 'auto' },
    table: { width: '100%', borderCollapse: 'collapse', fontSize: '12px' },
    th: { textAlign: 'left', padding: '8px', color: '#666', fontWeight: 500, borderBottom: '1px solid #222' },
    tr: { borderBottom: '1px solid rgba(255,255,255,0.03)' },
    td: { padding: '8px', color: '#ccc' },
    locBadge: { background: '#1a1a2e', padding: '2px 6px', borderRadius: '4px', fontSize: '10px', color: '#888' },
    killBtn: { background: 'transparent', color: '#ff3366', border: '1px solid #ff3366', padding: '4px 10px', borderRadius: '4px', fontSize: '10px', cursor: 'pointer', fontWeight: 600 },
    alertOverlay: { position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', background: 'rgba(255, 51, 102, 0.95)', zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center', animation: 'alertPulse 0.5s infinite' },
    alertBox: { background: '#1a0a10', padding: '50px 70px', borderRadius: '16px', border: '3px solid #ff3366', textAlign: 'center', boxShadow: '0 0 100px rgba(255,51,102,0.5)' },
    alertTitle: { fontSize: '32px', color: '#fff', marginBottom: '16px' },
    alertMessage: { fontSize: '18px', color: '#ffaaaa', marginBottom: '8px' },
    alertDetail: { fontSize: '14px', color: '#ff8888', marginBottom: '24px' },
    alertButton: { background: '#00ff88', color: '#000', border: 'none', padding: '16px 40px', borderRadius: '8px', fontSize: '14px', fontWeight: 700, cursor: 'pointer', boxShadow: '0 0 30px rgba(0,255,136,0.4)' }
};

export default App;