import React, { useState, useEffect } from 'react';
import { MessageSquare, RefreshCw, ArrowRight } from 'lucide-react';
import { SectionHeader, Card, EmptyState, LoadingSpinner, Pagination } from '../components/UI';
import { ProtoChip } from '../components/Badges';
import { getConversations, formatBytes } from '../services/api';
import type { Conversation } from '../types';
import { formatLocalDateTime, formatDuration, formatByteSize, formatRate } from '../utils/time';

export const Conversations: React.FC = () => {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [protocol, setProtocol] = useState('');
  const [ipFilter, setIpFilter] = useState('');
  const [sortBy, setSortBy] = useState('total_packets');
  const [page, setPage] = useState(1);
  const pageSize = 50;

  const invId = localStorage.getItem('selected_inv') || '';

  const loadData = async () => {
    if (!invId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await getConversations(invId, {
        protocol: protocol || undefined,
        ip: ipFilter || undefined,
        sort_by: sortBy,
        page,
      });
      setConversations(res.conversations);
      setTotal(res.total);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId, protocol, ipFilter, sortBy, page]);

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Flow Conversations"
          subtitle="Bi-directional network sessions and socket communications"
          icon={<MessageSquare size={18} />}
        />
        <Card>
          <EmptyState
            icon={<MessageSquare size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to inspect socket pairs and bidirectional flow conversations."
          />
        </Card>
      </div>
    );
  }

  return (
    <div className="fade-in space-y-4 max-w-7xl mx-auto">
      <SectionHeader
        title="Flow Conversations & Session Timeline"
        subtitle={`${total.toLocaleString()} bidirectional socket sessions analyzed with timing and bandwidth telemetry`}
        icon={<MessageSquare size={18} />}
        actions={
          <button className="btn-ghost" onClick={loadData} style={{ fontSize: 12 }}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        }
      />

      {/* Filter Toolbar */}
      <Card>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
              Protocol
            </label>
            <select
              className="soc-input"
              style={{ width: 130 }}
              value={protocol}
              onChange={(e) => {
                setProtocol(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All Protocols</option>
              {['TCP', 'UDP', 'DNS', 'HTTP', 'ICMP', 'TLS'].map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
              Host IP Filter
            </label>
            <input
              className="soc-input"
              style={{ width: 170 }}
              placeholder="e.g. 192.168.1.1"
              value={ipFilter}
              onChange={(e) => {
                setIpFilter(e.target.value);
                setPage(1);
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
              Sort Criteria
            </label>
            <select
              className="soc-input"
              style={{ width: 190 }}
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
            >
              <option value="total_bytes">Most Traffic</option>
              <option value="total_packets">Most Packets</option>
              <option value="duration">Longest Duration</option>
              <option value="connections">Most Connections</option>
              <option value="latest_activity">Latest Activity</option>
            </select>
          </div>

          <button
            className="btn-ghost"
            style={{ fontSize: 12 }}
            onClick={() => {
              setProtocol('');
              setIpFilter('');
              setSortBy('total_packets');
              setPage(1);
            }}
          >
            Clear Filters
          </button>
        </div>
      </Card>

      {/* Conversations Table */}
      <Card style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={30} />
          </div>
        ) : conversations.length === 0 ? (
          <EmptyState
            icon={<MessageSquare size={40} />}
            title="No Conversations Found"
            message="No communicating session pairs match the filter parameters."
          />
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ minWidth: 160 }}>Endpoint A (Source)</th>
                    <th style={{ minWidth: 160 }}>Endpoint B (Destination)</th>
                    <th>Protocol</th>
                    <th>First Activity</th>
                    <th>Last Activity</th>
                    <th>Duration</th>
                    <th style={{ textAlign: 'right' }}>Packets</th>
                    <th style={{ textAlign: 'right' }}>Total Volume</th>
                    <th style={{ textAlign: 'right' }}>Average Rate</th>
                    <th style={{ width: 130 }}>Directional Ratio</th>
                    <th>TCP Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {conversations.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <div style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--accent)', fontWeight: 600 }}>
                          {c.src_ip}
                          {c.src_port && <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>:{c.src_port}</span>}
                        </div>
                      </td>
                      <td>
                        <div style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--text-primary)', fontWeight: 600 }}>
                          {c.dst_ip}
                          {c.dst_port && <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>:{c.dst_port}</span>}
                        </div>
                      </td>
                      <td>
                        <ProtoChip protocol={c.protocol} />
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                        {c.start_time ? formatLocalDateTime(c.start_time) : '—'}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                        {c.end_time ? formatLocalDateTime(c.end_time) : '—'}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#10b981', fontWeight: 600 }}>
                        {formatDuration(c.duration)}
                      </td>
                      <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono', fontSize: 12, fontWeight: 600 }}>
                        {c.total_packets.toLocaleString()}
                      </td>
                      <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono', fontSize: 12, fontWeight: 600 }}>
                        {formatByteSize(c.total_bytes)}
                      </td>
                      <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                        {c.bytes_per_second != null ? formatRate(c.bytes_per_second) : '—'}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-secondary)' }}>
                        {c.packets_a_to_b} → / ← {c.packets_b_to_a}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {c.syn_count > 0 && (
                            <span style={{ fontSize: 9.5, padding: '1px 5px', borderRadius: 3, background: 'rgba(59,130,246,0.15)', color: '#60a5fa', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
                              SYN: {c.syn_count}
                            </span>
                          )}
                          {c.fin_count > 0 && (
                            <span style={{ fontSize: 9.5, padding: '1px 5px', borderRadius: 3, background: 'rgba(139,92,246,0.15)', color: '#a78bfa', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
                              FIN: {c.fin_count}
                            </span>
                          )}
                          {c.rst_count > 0 && (
                            <span style={{ fontSize: 9.5, padding: '1px 5px', borderRadius: 3, background: 'rgba(239,68,68,0.15)', color: '#f87171', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
                              RST: {c.rst_count}
                            </span>
                          )}
                          {c.syn_count === 0 && c.fin_count === 0 && c.rst_count === 0 && (
                            <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>—</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ padding: '0 16px' }}>
              <Pagination
                page={page}
                pages={Math.ceil(total / pageSize)}
                total={total}
                pageSize={pageSize}
                onChange={setPage}
              />
            </div>
          </>
        )}
      </Card>
    </div>
  );
};

export default Conversations;
