import React, { useState, useEffect } from 'react';
import { Search, Terminal, Server, Layers } from 'lucide-react';
import { SectionHeader, Card, EmptyState, LoadingSpinner, Pagination, Drawer } from '../components/UI';
import { ProtoChip } from '../components/Badges';
import { getPackets } from '../services/api';
import type { Packet } from '../types';
import { formatPreciseTimestamp } from '../utils/time';

export const PacketExplorer: React.FC = () => {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Packet | null>(null);
  const [page, setPage] = useState(1);
  const pageSize = 100;

  // Filters
  const [protocol, setProtocol] = useState('');
  const [srcIp, setSrcIp] = useState('');
  const [dstIp, setDstIp] = useState('');
  const [dstPort, setDstPort] = useState('');

  const invId = localStorage.getItem('selected_inv') || '';

  useEffect(() => {
    if (!invId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    getPackets(invId, {
      page,
      page_size: pageSize,
      protocol: protocol || undefined,
      src_ip: srcIp || undefined,
      dst_ip: dstIp || undefined,
      dst_port: dstPort ? parseInt(dstPort) : undefined,
    })
      .then((res) => {
        setPackets(res.packets);
        setTotal(res.total);
        setPages(res.pages);
      })
      .finally(() => setLoading(false));
  }, [invId, page, protocol, srcIp, dstIp, dstPort]);

  const FLAG_COLORS: Record<string, string> = {
    SYN: '#3b82f6',
    ACK: '#10b981',
    FIN: '#8b5cf6',
    RST: '#ef4444',
    PSH: '#f59e0b',
    URG: '#ec4899',
  };

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Packet Explorer"
          subtitle="Wireshark-grade deep packet inspection and protocol header decoding"
          icon={<Search size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Search size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to inspect dissected frames, protocol flags, and payload summaries."
          />
        </Card>
      </div>
    );
  }

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="Packet Explorer"
        subtitle={`${total.toLocaleString()} dissected frames matching filter criteria`}
        icon={<Search size={18} />}
      />

      {/* Filter Control Bar */}
      <Card>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              Protocol
            </label>
            <select
              className="soc-input"
              style={{ width: 110 }}
              value={protocol}
              onChange={(e) => {
                setProtocol(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All</option>
              {['TCP', 'UDP', 'DNS', 'HTTP', 'ICMP', 'ARP', 'TLS'].map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              Source IP
            </label>
            <input
              className="soc-input"
              style={{ width: 140 }}
              placeholder="e.g. 192.168.1.1"
              value={srcIp}
              onChange={(e) => {
                setSrcIp(e.target.value);
                setPage(1);
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              Destination IP
            </label>
            <input
              className="soc-input"
              style={{ width: 140 }}
              placeholder="e.g. 8.8.8.8"
              value={dstIp}
              onChange={(e) => {
                setDstIp(e.target.value);
                setPage(1);
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              Port
            </label>
            <input
              className="soc-input"
              style={{ width: 90 }}
              placeholder="e.g. 443"
              type="number"
              value={dstPort}
              onChange={(e) => {
                setDstPort(e.target.value);
                setPage(1);
              }}
            />
          </div>

          <button
            className="btn-ghost"
            style={{ fontSize: 12 }}
            onClick={() => {
              setProtocol('');
              setSrcIp('');
              setDstIp('');
              setDstPort('');
              setPage(1);
            }}
          >
            Clear Filters
          </button>
        </div>
      </Card>

      {/* High Density Packet Table */}
      <Card style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={30} />
          </div>
        ) : packets.length === 0 ? (
          <EmptyState
            icon={<Search size={40} />}
            title="No Matching Packets"
            message="No captured frames match the specified filter criteria."
          />
        ) : (
          <>
            <table className="data-table" style={{ tableLayout: 'fixed' }}>
              <thead>
                <tr>
                  <th style={{ width: 65 }}>#</th>
                  <th style={{ width: 140 }}>Timestamp</th>
                  <th style={{ width: 170 }}>Source</th>
                  <th style={{ width: 170 }}>Destination</th>
                  <th style={{ width: 85 }}>Protocol</th>
                  <th style={{ width: 75 }}>Length</th>
                  <th style={{ width: 95 }}>TCP Flags</th>
                  <th>Info / Summary</th>
                </tr>
              </thead>
              <tbody>
                {packets.map((p) => {
                  const isSelected = selected?.id === p.id;
                  return (
                    <tr
                      key={p.id}
                      style={{
                        cursor: 'pointer',
                        background: isSelected ? 'rgba(6, 182, 212, 0.1)' : undefined,
                      }}
                      onClick={() => setSelected(p)}
                    >
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                        {p.frame_number}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10.5, color: 'var(--text-primary)', fontWeight: 600 }}>
                        {formatPreciseTimestamp(p.timestamp_str || p.timestamp)}
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                          <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--accent)' }}>
                            {p.src_ip || '—'}
                          </span>
                          {p.src_port && (
                            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                              :{p.src_port}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                          <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--text-primary)' }}>
                            {p.dst_ip || '—'}
                          </span>
                          {p.dst_port && (
                            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                              :{p.dst_port}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <ProtoChip protocol={p.protocol} />
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11 }}>
                        {p.length} B
                      </td>
                      <td>
                        {p.tcp_flags ? (
                          <div style={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                            {p.tcp_flags.split('-').map((f) => (
                              <span
                                key={f}
                                style={{
                                  fontSize: 9,
                                  padding: '1px 3px',
                                  borderRadius: 2,
                                  background: `${FLAG_COLORS[f] || '#64748b'}20`,
                                  color: FLAG_COLORS[f] || 'var(--text-muted)',
                                  fontWeight: 700,
                                  fontFamily: 'JetBrains Mono',
                                }}
                              >
                                {f}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-dim)' }}>—</span>
                        )}
                      </td>
                      <td
                        style={{
                          fontSize: 11.5,
                          fontFamily: 'JetBrains Mono',
                          color: 'var(--text-secondary)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {p.info || '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            <div style={{ padding: '0 16px' }}>
              <Pagination
                page={page}
                pages={pages}
                total={total}
                pageSize={pageSize}
                onChange={setPage}
              />
            </div>
          </>
        )}
      </Card>

      {/* Packet Detail Slide-Over Drawer */}
      <Drawer
        isOpen={!!selected}
        onClose={() => setSelected(null)}
        title={`Frame #${selected?.frame_number || ''} Inspector`}
        subtitle={`${selected?.protocol || ''} Packet Dissection`}
        width={560}
      >
        {selected && (
          <div className="space-y-4">
            {/* Layer 1: Physical Frame */}
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                <Layers size={13} /> Frame Metadata
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 11.5 }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Frame Number: </span>
                  <span style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>#{selected.frame_number}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Captured Length: </span>
                  <span style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>{selected.length} bytes</span>
                </div>
                <div style={{ gridColumn: 'span 2' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Arrival Time: </span>
                  <span style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>{selected.timestamp_str || String(selected.timestamp)}</span>
                </div>
              </div>
            </div>

            {/* Layer 2: Network / IP Layer */}
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                <Server size={13} /> Internet Protocol (IPv4 / IPv6)
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 11.5 }}>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Source Address</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--accent)', fontWeight: 600 }}>{selected.src_ip || '—'}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Destination Address</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600 }}>{selected.dst_ip || '—'}</div>
                </div>
              </div>
            </div>

            {/* Layer 3: Transport Layer */}
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, fontWeight: 700, color: '#a78bfa', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                <Terminal size={13} /> Transport Protocol ({selected.protocol})
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 11.5 }}>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Source Port</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>{selected.src_port || '—'}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Destination Port</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>{selected.dst_port || '—'}</div>
                </div>
                {selected.tcp_flags && (
                  <div style={{ gridColumn: 'span 2' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: 10.5, marginBottom: 2 }}>TCP Flags</div>
                    <div style={{ display: 'flex', gap: 4 }}>
                      {selected.tcp_flags.split('-').map((f) => (
                        <span key={f} style={{ fontSize: 10, padding: '2px 6px', borderRadius: 3, background: `${FLAG_COLORS[f] || '#64748b'}25`, color: FLAG_COLORS[f] || '#fff', fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
                          {f}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Layer 4: Application / Info */}
            {selected.info && (
              <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
                <div style={{ fontSize: 11.5, fontWeight: 700, color: '#34d399', textTransform: 'uppercase', marginBottom: 6, letterSpacing: '0.04em' }}>
                  Decoded Application Payload Summary
                </div>
                <div style={{ fontSize: 11.5, fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', background: '#070b14', padding: 10, borderRadius: 4, wordBreak: 'break-all', lineHeight: 1.5, border: '1px solid var(--border-subtle)' }}>
                  {selected.info}
                </div>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
};

export default PacketExplorer;
