import React, { useState, useEffect } from 'react';
import { Terminal, RefreshCw, AlertTriangle, Wifi } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { SectionHeader, Card, KPICard, EmptyState, LoadingSpinner } from '../components/UI';
import { getTCP } from '../services/api';

const WELL_KNOWN: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
};

export const TCPPage: React.FC = () => {
  const [tcp, setTcp] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const invId = localStorage.getItem('selected_inv') || '';

  const loadData = async () => {
    if (!invId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const t = await getTCP(invId);
      setTcp(t);
    } catch {
      setTcp(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId]);

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="TCP Transport Analysis"
          subtitle="Transmission Control Protocol stream metrics, handshake rates, and flags"
          icon={<Terminal size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Terminal size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to inspect TCP handshake telemetry and flag distributions."
          />
        </Card>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="TCP Transport Analysis"
          subtitle="Transmission Control Protocol stream metrics, handshake rates, and flags"
          icon={<Terminal size={18} />}
        />
        <Card>
          <div style={{ display: 'flex', justifyContent: 'center', padding: '64px 0' }}>
            <LoadingSpinner size={32} />
          </div>
        </Card>
      </div>
    );
  }

  const tcpFlags = tcp
    ? [
        { name: 'SYN', value: tcp.syn_count || 0, color: '#3b82f6' },
        { name: 'SYN-ACK', value: tcp.syn_ack_count || 0, color: '#06b6d4' },
        { name: 'ACK', value: tcp.ack_count || 0, color: '#10b981' },
        { name: 'PSH', value: tcp.psh_count || 0, color: '#f59e0b' },
        { name: 'FIN', value: tcp.fin_count || 0, color: '#8b5cf6' },
        { name: 'RST', value: tcp.rst_count || 0, color: '#ef4444' },
      ]
    : [];

  const topPorts = (tcp?.top_destination_ports || []).map(([p, c]: [number, number]) => ({
    port: `${p}`,
    count: c,
    service: WELL_KNOWN[p] || 'Custom / Ephemeral',
  }));

  const rstRatio =
    tcp && tcp.syn_count > 0 ? ((tcp.rst_count / tcp.syn_count) * 100).toFixed(1) : '0';

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="TCP Transport Analysis"
        subtitle={`${(tcp?.total_tcp_packets || 0).toLocaleString()} TCP segment headers dissected`}
        icon={<Terminal size={18} />}
        actions={
          <button className="btn-ghost" onClick={loadData} style={{ fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        }
      />

      {/* Top TCP KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12 }}>
        <KPICard
          label="Total TCP Packets"
          value={tcp?.total_tcp_packets || 0}
          icon={<Terminal size={18} />}
          color="#3b82f6"
          subtitle="Transport segments"
        />
        <KPICard
          label="Est. Connections"
          value={tcp?.estimated_connections || 0}
          icon={<Wifi size={18} />}
          color="#10b981"
          subtitle="Handshakes observed"
        />
        <KPICard
          label="SYN Packets"
          value={tcp?.syn_count || 0}
          icon={<Terminal size={18} />}
          color="#06b6d4"
          subtitle="Connection attempts"
        />
        <KPICard
          label="RST Resets"
          value={tcp?.rst_count || 0}
          icon={<AlertTriangle size={18} />}
          color={tcp?.rst_count > 20 ? '#ef4444' : '#f59e0b'}
          subtitle={`RST/SYN: ${rstRatio}%`}
        />
      </div>

      {/* Charts: Flag Distribution & Top Ports */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* TCP Flag Distribution Chart */}
        <Card>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            TCP Control Flags Distribution
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
            SYN vs RST anomalies often reveal scanning probes
          </div>

          <ResponsiveContainer width="100%" height={230}>
            <BarChart data={tcpFlags} layout="vertical" margin={{ left: 20, right: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} stroke="var(--border)" />
              <YAxis dataKey="name" type="category" tick={{ fill: 'var(--text-primary)', fontSize: 11, fontFamily: 'JetBrains Mono' }} width={70} stroke="var(--border)" />
              <Tooltip
                contentStyle={{
                  background: '#0f172a',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  fontSize: 11.5,
                  fontFamily: 'JetBrains Mono',
                }}
                formatter={(val: any) => [val, 'Packets']}
              />
              <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={16} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Top Destination Ports Table */}
        <Card style={{ padding: 0 }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)' }}>
              Targeted Destination Ports
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Most targeted transport layer services</div>
          </div>

          {topPorts.length === 0 ? (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
              No TCP destination port data captured.
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 100 }}>Port</th>
                  <th>Service Identity</th>
                  <th style={{ width: 120 }}>Packets</th>
                </tr>
              </thead>
              <tbody>
                {topPorts.slice(0, 8).map((p: any) => (
                  <tr key={p.port}>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>
                        Port {p.port}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 12, color: 'var(--text-primary)' }}>
                        {p.service}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                      {p.count.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </div>
  );
};

export default TCPPage;
