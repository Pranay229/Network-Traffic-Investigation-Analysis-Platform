import React, { useState, useEffect } from 'react';
import {
  Layers, Search, Shield, AlertTriangle, RefreshCw,
  Server, Globe, Terminal, CheckCircle2, Info
} from 'lucide-react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Cell
} from 'recharts';
import { SectionHeader, Card, KPICard, EmptyState, LoadingSpinner } from '../components/UI';
import {
  getInvestigationProtocols, getInvestigationARP, getInvestigationTLS, formatBytes
} from '../services/api';
import type {
  ProtocolAnalysisResponse, ARPRecordItem, TLSMetadataItem
} from '../types';

const PROTO_COLORS: Record<string, string> = {
  TCP: '#06b6d4',
  UDP: '#8b5cf6',
  ICMP: '#f59e0b',
  ARP: '#10b981',
  DNS: '#3b82f6',
  HTTP: '#ec4899',
  'HTTPS/TLS': '#6366f1',
  DHCP: '#14b8a6',
  SSH: '#f97316',
  FTP: '#eab308',
  SMTP: '#a855f7',
  SMB: '#ef4444',
  NTP: '#64748b',
  SNMP: '#0284c7',
  IPv4: '#0ea5e9',
  IPv6: '#8b5cf6',
};

export const Protocols: React.FC = () => {
  const [data, setData] = useState<ProtocolAnalysisResponse | null>(null);
  const [arpRecords, setArpRecords] = useState<ARPRecordItem[]>([]);
  const [tlsRecords, setTlsRecords] = useState<TLSMetadataItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [activeTab, setActiveTab] = useState<'protocols' | 'arp' | 'tls'>('protocols');

  const invId = localStorage.getItem('selected_inv') || '';

  const loadAll = async () => {
    if (!invId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const [protoRes, arpRes, tlsRes] = await Promise.all([
        getInvestigationProtocols(invId),
        getInvestigationARP(invId).catch(() => ({ total: 0, arp_records: [] })),
        getInvestigationTLS(invId).catch(() => ({ total: 0, tls_metadata: [] })),
      ]);
      setData(protoRes);
      setArpRecords(arpRes.arp_records || []);
      setTlsRecords(tlsRes.tls_metadata || []);
    } catch (err) {
      console.error('Failed to load protocol data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, [invId]);

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Protocol Analysis"
          subtitle="Network and application protocol classification, volume distribution, and anomaly detection"
          icon={<Layers size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Layers size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation from the Investigations workspace to view real protocol analysis."
          />
        </Card>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Protocol Analysis"
          subtitle="Classifying packet telemetry across Core, Web, Network Services, and Remote Access protocols"
          icon={<Layers size={18} />}
        />
        <Card>
          <div style={{ padding: 48, textAlign: 'center' }}>
            <LoadingSpinner size={36} />
            <p style={{ marginTop: 16, color: 'var(--text-muted)' }}>Analyzing protocol distribution from PCAP telemetry...</p>
          </div>
        </Card>
      </div>
    );
  }

  const allProtocols = data?.protocols || [];
  const filteredProtocols = allProtocols.filter(p => {
    const matchesSearch = p.protocol.toLowerCase().includes(search.toLowerCase());
    if (!matchesSearch) return false;
    if (selectedCategory === 'all') return true;
    if (selectedCategory === 'core') return ['IPv4', 'IPv6', 'TCP', 'UDP', 'ICMP', 'ARP'].includes(p.protocol);
    if (selectedCategory === 'web') return ['HTTP', 'HTTPS/TLS'].includes(p.protocol);
    if (selectedCategory === 'services') return ['DNS', 'DHCP', 'NTP', 'SNMP'].includes(p.protocol);
    if (selectedCategory === 'remote') return ['SSH', 'FTP', 'SMTP', 'SMB'].includes(p.protocol);
    return true;
  });

  const chartData = allProtocols.slice(0, 10).map(p => ({
    protocol: p.protocol,
    packets: p.packets,
    bytes: p.bytes,
    percentage: p.percentage,
  }));

  const corePackets = (data?.summary?.tcp_packets || 0) + (data?.summary?.udp_packets || 0) + (data?.summary?.icmp_packets || 0) + (data?.summary?.arp_packets || 0);
  const webPackets = (data?.summary?.http_packets || 0) + (data?.summary?.tls_packets || 0);
  const dnsPackets = data?.summary?.dns_packets || 0;
  const sshPackets = data?.summary?.ssh_packets || 0;

  return (
    <div className="fade-in space-y-5">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <SectionHeader
          title="Protocol Analysis"
          subtitle="Real-time protocol classification across Layer 2 through Layer 7 with telemetry parsing"
          icon={<Layers size={18} />}
        />
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => loadAll()}
            className="btn btn-secondary btn-sm"
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
        <KPICard
          label="Observed Protocols"
          value={allProtocols.length}
          icon={<Layers size={18} />}
          color="#06b6d4"
          subtitle={`${data?.total_packets.toLocaleString() || 0} total packets`}
        />
        <KPICard
          label="Core Traffic (TCP/UDP/ICMP)"
          value={corePackets}
          icon={<Server size={18} />}
          color="#8b5cf6"
          subtitle={`TCP: ${data?.summary?.tcp_packets.toLocaleString() || 0} | UDP: ${data?.summary?.udp_packets.toLocaleString() || 0}`}
        />
        <KPICard
          label="Web & Encrypted (HTTP/TLS)"
          value={webPackets}
          icon={<Globe size={18} />}
          color="#ec4899"
          subtitle={`TLS: ${data?.summary?.tls_packets.toLocaleString() || 0} | HTTP: ${data?.summary?.http_packets.toLocaleString() || 0}`}
        />
        <KPICard
          label="Network Resolution (DNS)"
          value={dnsPackets}
          icon={<Shield size={18} />}
          color="#3b82f6"
          subtitle={`ARP Packets: ${data?.summary?.arp_packets.toLocaleString() || 0}`}
        />
        <KPICard
          label="Remote Access (SSH)"
          value={sshPackets}
          icon={<Terminal size={18} />}
          color="#f97316"
          subtitle="Authorized sessions only"
        />
      </div>

      {/* Navigation Sub-Tabs */}
      <div style={{ display: 'flex', gap: 12, borderBottom: '1px solid var(--border)', paddingBottom: 8 }}>
        <button
          onClick={() => setActiveTab('protocols')}
          className={`btn btn-sm ${activeTab === 'protocols' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Layers size={14} /> Protocol Distribution ({allProtocols.length})
        </button>
        <button
          onClick={() => setActiveTab('arp')}
          className={`btn btn-sm ${activeTab === 'arp' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Server size={14} /> ARP Resolution & Anomalies ({arpRecords.length})
        </button>
        <button
          onClick={() => setActiveTab('tls')}
          className={`btn btn-sm ${activeTab === 'tls' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Globe size={14} /> TLS / HTTPS Handshakes ({tlsRecords.length})
        </button>
      </div>

      {activeTab === 'protocols' && (
        <>
          {/* Chart & Distribution */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 16 }}>
            <Card title="Top Protocols by Packet Volume">
              <div style={{ height: 260, width: '100%', marginTop: 8 }}>
                {chartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 25 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" opacity={0.4} />
                      <XAxis
                        dataKey="protocol"
                        stroke="var(--text-muted)"
                        tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                        angle={-25}
                        textAnchor="end"
                      />
                      <YAxis
                        stroke="var(--text-muted)"
                        tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: 'var(--bg-card)',
                          borderColor: 'var(--border)',
                          borderRadius: 6,
                          color: 'var(--text-primary)'
                        }}
                        formatter={(val: any) => [Number(val).toLocaleString() + ' packets', 'Volume']}
                      />
                      <Bar dataKey="packets" radius={[4, 4, 0, 0]}>
                        {chartData.map((entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={PROTO_COLORS[entry.protocol] || '#06b6d4'}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <EmptyState title="No Protocol Data" message="No packets parsed for distribution chart." />
                )}
              </div>
            </Card>

            <Card title="Traffic Category Summary">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginTop: 12 }}>
                <div style={{ padding: '10px 14px', background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 600, fontSize: 13, color: '#06b6d4' }}>Core Network Protocols</span>
                    <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{corePackets.toLocaleString()} packets</span>
                  </div>
                  <p style={{ margin: 0, fontSize: 11.5, color: 'var(--text-muted)' }}>
                    IPv4, IPv6, TCP, UDP, ICMP, ARP underlying transmission data.
                  </p>
                </div>

                <div style={{ padding: '10px 14px', background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 600, fontSize: 13, color: '#ec4899' }}>Web & Encrypted Traffic</span>
                    <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{webPackets.toLocaleString()} packets</span>
                  </div>
                  <p style={{ margin: 0, fontSize: 11.5, color: 'var(--text-muted)' }}>
                    Standard HTTP and encrypted TLS sessions (SNI & handshake analysis without payload decryption).
                  </p>
                </div>

                <div style={{ padding: '10px 14px', background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 600, fontSize: 13, color: '#3b82f6' }}>Network Services & Management</span>
                    <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{dnsPackets.toLocaleString()} DNS queries</span>
                  </div>
                  <p style={{ margin: 0, fontSize: 11.5, color: 'var(--text-muted)' }}>
                    DNS resolutions, DHCP lease negotiations, NTP time sync, SNMP management telemetry.
                  </p>
                </div>

                <div style={{ padding: '10px 14px', background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 600, fontSize: 13, color: '#f97316' }}>Remote Access & File Transfer</span>
                    <span style={{ fontSize: 12, fontFamily: 'monospace' }}>{sshPackets.toLocaleString()} packets</span>
                  </div>
                  <p style={{ margin: 0, fontSize: 11.5, color: 'var(--text-muted)' }}>
                    SSH secure shells, FTP transfers, SMB shares, SMTP mail relay. Zero credential extraction.
                  </p>
                </div>
              </div>
            </Card>
          </div>

          {/* Filter Bar */}
          <Card>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 260 }}>
                <Search size={16} style={{ color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  placeholder="Filter by protocol name..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="input"
                  style={{ width: '100%', maxWidth: 300 }}
                />
              </div>

              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {[
                  { id: 'all', label: 'All Protocols' },
                  { id: 'core', label: 'Core Network' },
                  { id: 'web', label: 'Web (HTTP/TLS)' },
                  { id: 'services', label: 'Network Services' },
                  { id: 'remote', label: 'Remote / Files' },
                ].map(cat => (
                  <button
                    key={cat.id}
                    onClick={() => setSelectedCategory(cat.id)}
                    className={`btn btn-xs ${selectedCategory === cat.id ? 'btn-primary' : 'btn-secondary'}`}
                  >
                    {cat.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Protocol Detail Table */}
            <div style={{ overflowX: 'auto', marginTop: 16 }}>
              <table className="table" style={{ width: '100%' }}>
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Packets</th>
                    <th>Bytes</th>
                    <th>Volume Share (%)</th>
                    <th>First Observed</th>
                    <th>Last Observed</th>
                    <th>Security Observation</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredProtocols.length > 0 ? (
                    filteredProtocols.map(p => {
                      const color = PROTO_COLORS[p.protocol] || '#64748b';
                      return (
                        <tr key={p.protocol}>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <span
                                style={{
                                  width: 10,
                                  height: 10,
                                  borderRadius: '50%',
                                  backgroundColor: color,
                                  display: 'inline-block'
                                }}
                              />
                              <span style={{ fontWeight: 600, fontFamily: 'monospace' }}>{p.protocol}</span>
                            </div>
                          </td>
                          <td style={{ fontFamily: 'monospace' }}>{p.packets.toLocaleString()}</td>
                          <td style={{ fontFamily: 'monospace' }}>{formatBytes(p.bytes)}</td>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <div
                                style={{
                                  flex: 1,
                                  height: 6,
                                  background: 'var(--bg-secondary)',
                                  borderRadius: 3,
                                  overflow: 'hidden'
                                }}
                              >
                                <div
                                  style={{
                                    width: `${Math.min(100, p.percentage)}%`,
                                    height: '100%',
                                    backgroundColor: color
                                  }}
                                />
                              </div>
                              <span style={{ fontSize: 12, fontFamily: 'monospace', minWidth: 42 }}>
                                {p.percentage.toFixed(1)}%
                              </span>
                            </div>
                          </td>
                          <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {p.first_seen || 'N/A'}
                          </td>
                          <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {p.last_seen || 'N/A'}
                          </td>
                          <td>
                            <span style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                              Observed in capture baseline
                            </span>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>
                        No protocols match the active filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}

      {activeTab === 'arp' && (
        <Card title="ARP Address Mapping & Inconsistency Tracking">
          <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Info size={16} style={{ color: '#06b6d4' }} />
            <span style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>
              Tracking IP-to-MAC associations. An inconsistency alert is raised when multiple MACs claim an IP address.
            </span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>MAC Address</th>
                  <th>Opcode</th>
                  <th>Packets</th>
                  <th>First Seen</th>
                  <th>Last Seen</th>
                  <th>Consistency Status</th>
                </tr>
              </thead>
              <tbody>
                {arpRecords.length > 0 ? (
                  arpRecords.map((r, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{r.ip_address}</td>
                      <td style={{ fontFamily: 'monospace' }}>{r.mac_address}</td>
                      <td>
                        <span style={{ padding: '1px 6px', borderRadius: 4, background: 'var(--bg-secondary)', border: '1px solid var(--border)', fontSize: 11, fontFamily: 'monospace' }}>{r.opcode}</span>
                      </td>
                      <td style={{ fontFamily: 'monospace' }}>{r.packet_count}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{r.first_seen}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{r.last_seen}</td>
                      <td>
                        {r.is_inconsistent ? (
                          <span style={{ color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                            <AlertTriangle size={14} /> Potential Inconsistency
                          </span>
                        ) : (
                          <span style={{ color: 'var(--success)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                            <CheckCircle2 size={14} /> Consistent
                          </span>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>
                      No ARP frames recorded in this investigation.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {activeTab === 'tls' && (
        <Card title="TLS / HTTPS Handshake Metadata">
          <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Shield size={16} style={{ color: '#10b981' }} />
            <span style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>
              Non-intrusive TLS handshake telemetry (SNI, negotiated version, cipher suite) without payload decryption.
            </span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Port</th>
                  <th>Server Name Indication (SNI)</th>
                  <th>TLS Version</th>
                  <th>Cipher Suite</th>
                </tr>
              </thead>
              <tbody>
                {tlsRecords.length > 0 ? (
                  tlsRecords.map((t, idx) => (
                    <tr key={idx}>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{t.timestamp}</td>
                      <td style={{ fontFamily: 'monospace' }}>{t.src_ip}</td>
                      <td style={{ fontFamily: 'monospace' }}>{t.dst_ip}</td>
                      <td style={{ fontFamily: 'monospace' }}>{t.dst_port}</td>
                      <td style={{ fontFamily: 'monospace', color: '#06b6d4' }}>
                        {t.sni || <span style={{ color: 'var(--text-muted)' }}>None / IP direct</span>}
                      </td>
                      <td>
                        <span style={{ padding: '1px 6px', borderRadius: 4, background: 'var(--bg-secondary)', border: '1px solid var(--border)', fontSize: 11, fontFamily: 'monospace' }}>{t.tls_version || 'TLS'}</span>
                      </td>
                      <td style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                        {t.cipher_suite || 'Standard Negotiated'}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>
                      No TLS handshakes recorded in this investigation.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
};

export default Protocols;
