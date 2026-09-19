import React, { useState, useEffect } from 'react';
import { Radio, AlertTriangle, Shield, RefreshCw } from 'lucide-react';
import { SectionHeader, Card, KPICard, EmptyState, LoadingSpinner, Pagination } from '../components/UI';
import { getICMP } from '../services/api';
import type { ICMPResponse } from '../types';

export const ICMPPage: React.FC = () => {
  const [data, setData] = useState<ICMPResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [srcFilter, setSrcFilter] = useState('');
  const [dstFilter, setDstFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
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
      const res = await getICMP(invId);
      setData(res);
    } catch {
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId]);

  if (!invId) {
    return (
      <div className="fade-in">
        <SectionHeader
          title="ICMP Investigation"
          subtitle="Internet Control Message Protocol & Ping Flooding Telemetry"
          icon={<Radio size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Radio size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation or upload a PCAP file to analyze ICMP control messages and ping traffic."
          />
        </Card>
      </div>
    );
  }

  const records = data?.records || [];
  const summary = data?.summary || {
    total_icmp_packets: 0,
    echo_requests: 0,
    echo_replies: 0,
    unreachable: 0,
    ttl_exceeded: 0,
    other_icmp: 0,
    suspicious_volume: false,
  };

  const filteredRecords = records.filter((r) => {
    if (srcFilter && (!r.src_ip || !r.src_ip.toLowerCase().includes(srcFilter.toLowerCase()))) return false;
    if (dstFilter && (!r.dst_ip || !r.dst_ip.toLowerCase().includes(dstFilter.toLowerCase()))) return false;
    if (typeFilter && r.icmp_type_name !== typeFilter) return false;
    return true;
  });

  const totalPages = Math.ceil(filteredRecords.length / pageSize);
  const paginatedRecords = filteredRecords.slice((page - 1) * pageSize, page * pageSize);

  const distinctTypes = Array.from(new Set(records.map((r) => r.icmp_type_name).filter(Boolean))) as string[];

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="ICMP Investigation"
        subtitle={`${summary.total_icmp_packets.toLocaleString()} ICMP control packets captured`}
        icon={<Radio size={18} />}
        actions={
          <button className="btn-ghost" onClick={loadData} style={{ fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        }
      />

      {/* KPI Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12 }}>
        <KPICard
          label="Total ICMP"
          value={summary.total_icmp_packets}
          icon={<Radio size={18} />}
          color="#f97316"
        />
        <KPICard
          label="Echo Requests"
          value={summary.echo_requests}
          icon={<Radio size={18} />}
          color="#06b6d4"
          subtitle="Ping Initiations (Type 8)"
        />
        <KPICard
          label="Echo Replies"
          value={summary.echo_replies}
          icon={<Radio size={18} />}
          color="#10b981"
          subtitle="Ping Responses (Type 0)"
        />
        <KPICard
          label="Unreachable"
          value={summary.unreachable}
          icon={<AlertTriangle size={18} />}
          color="#f59e0b"
          subtitle="Dest Unreachable (Type 3)"
        />
        <KPICard
          label="TTL Exceeded"
          value={summary.ttl_exceeded}
          icon={<AlertTriangle size={18} />}
          color="#ef4444"
          subtitle="Traceroute / Loop (Type 11)"
        />
        <KPICard
          label="Anomaly Status"
          value={summary.suspicious_volume ? 'SUSPICIOUS' : 'NOMINAL'}
          icon={<Shield size={18} />}
          color={summary.suspicious_volume ? '#ef4444' : '#10b981'}
          subtitle={summary.suspicious_volume ? 'High ICMP rate' : 'Baseline volume'}
        />
      </div>

      {/* Suspicious Rate Warning Banner */}
      {summary.suspicious_volume && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '12px 16px',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 8,
            color: '#f87171',
            fontSize: 12.5,
          }}
        >
          <AlertTriangle size={16} className="shrink-0" />
          <div>
            <strong>High ICMP Traffic Volume Detected:</strong> An unusually high volume of ICMP packets exceeds the detection threshold. This pattern frequently indicates an active ping sweep, ICMP tunneling, or Smurf denial-of-service attack.
          </div>
        </div>
      )}

      {/* Filters Card */}
      <Card>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              ICMP Type
            </label>
            <select
              className="soc-input"
              style={{ width: 170 }}
              value={typeFilter}
              onChange={(e) => {
                setTypeFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All ICMP Types</option>
              {distinctTypes.map((t) => (
                <option key={t} value={t}>
                  {t}
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
              style={{ width: 150 }}
              placeholder="e.g. 192.168.1.1"
              value={srcFilter}
              onChange={(e) => {
                setSrcFilter(e.target.value);
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
              style={{ width: 150 }}
              placeholder="e.g. 192.168.1.254"
              value={dstFilter}
              onChange={(e) => {
                setDstFilter(e.target.value);
                setPage(1);
              }}
            />
          </div>

          <button
            className="btn-ghost"
            style={{ fontSize: 12 }}
            onClick={() => {
              setSrcFilter('');
              setDstFilter('');
              setTypeFilter('');
              setPage(1);
            }}
          >
            Clear Filters
          </button>
        </div>
      </Card>

      {/* Data Table */}
      <Card style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
            <LoadingSpinner size={28} />
          </div>
        ) : filteredRecords.length === 0 ? (
          <EmptyState
            icon={<Radio size={40} />}
            title="No ICMP Records Found"
            message={
              records.length === 0
                ? 'No ICMP packets were captured in this trace.'
                : 'No ICMP records match your filter criteria.'
            }
          />
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 140 }}>Timestamp</th>
                  <th style={{ width: 160 }}>Source IP</th>
                  <th style={{ width: 160 }}>Destination IP</th>
                  <th style={{ width: 100 }}>Type / Code</th>
                  <th>ICMP Type Name</th>
                  <th style={{ width: 90 }}>Length</th>
                </tr>
              </thead>
              <tbody>
                {paginatedRecords.map((r) => (
                  <tr key={r.id}>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                      {r.timestamp_str || String(r.timestamp)}
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--accent)' }}>
                        {r.src_ip || '—'}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--text-primary)' }}>
                        {r.dst_ip || '—'}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: 'JetBrains Mono',
                          fontSize: 11,
                          padding: '1px 6px',
                          borderRadius: 3,
                          background: 'rgba(255, 255, 255, 0.05)',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {r.icmp_type ?? '—'}:{r.icmp_code ?? '—'}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontSize: 12,
                          fontWeight: 600,
                          color:
                            r.icmp_type === 8
                              ? '#38bdf8'
                              : r.icmp_type === 0
                              ? '#34d399'
                              : r.icmp_type === 3
                              ? '#fbbf24'
                              : r.icmp_type === 11
                              ? '#f87171'
                              : 'var(--text-secondary)',
                        }}
                      >
                        {r.icmp_type_name || 'ICMP Control'}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                      {r.length} B
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div style={{ padding: '0 16px' }}>
              <Pagination
                page={page}
                pages={totalPages}
                total={filteredRecords.length}
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

export default ICMPPage;
