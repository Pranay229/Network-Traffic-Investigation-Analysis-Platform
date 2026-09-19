import React, { useState, useEffect } from 'react';
import { Globe, Search, AlertTriangle, RefreshCw } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts';
import { SectionHeader, Card, KPICard, EmptyState, LoadingSpinner, Pagination } from '../components/UI';
import { getDNS } from '../services/api';
import type { DNSRecord } from '../types';

export const DNS: React.FC = () => {
  const [records, setRecords] = useState<DNSRecord[]>([]);
  const [summary, setSummary] = useState<any>({});
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
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
      const res = await getDNS(invId, { search, page });
      setRecords(res.records);
      setSummary(res.summary || {});
      setTotal(res.total);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId, search, page]);

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="DNS Investigation"
          subtitle="Domain Name System resolutions, queries, and suspicious lookups"
          icon={<Globe size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Globe size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to inspect DNS query records and resolution telemetry."
          />
        </Card>
      </div>
    );
  }

  // Calculate top domains for frequency chart
  const domainCounts: Record<string, number> = {};
  records.forEach((r) => {
    if (r.query_name) {
      domainCounts[r.query_name] = (domainCounts[r.query_name] || 0) + 1;
    }
  });

  const topDomainList = Object.entries(domainCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([domain, count]) => ({
      domain: domain.length > 24 ? domain.slice(0, 22) + '...' : domain,
      count,
    }));

  const uniqueDomainsCount = summary.unique_domains || Object.keys(domainCounts).length;
  const topDomain = summary.top_domain || (topDomainList[0]?.domain || '—');
  const suspiciousDnsCount = summary.suspicious_queries || 0;

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="DNS Investigation"
        subtitle={`${total.toLocaleString()} DNS queries and responses decoded`}
        icon={<Globe size={18} />}
        actions={
          <button className="btn-ghost" onClick={loadData} style={{ fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        }
      />

      {/* Top Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
        <KPICard
          label="Total Queries"
          value={total}
          icon={<Globe size={18} />}
          color="#06b6d4"
          subtitle="All DNS frames"
        />
        <KPICard
          label="Unique Domains"
          value={uniqueDomainsCount}
          icon={<Globe size={18} />}
          color="#10b981"
          subtitle="Distinct hosts queried"
        />
        <KPICard
          label="Top Queried Domain"
          value={topDomain}
          icon={<Globe size={18} />}
          color="#3b82f6"
          subtitle="Most frequent host"
        />
        <KPICard
          label="Suspicious Queries"
          value={suspiciousDnsCount}
          icon={<AlertTriangle size={18} />}
          color={suspiciousDnsCount > 0 ? '#ef4444' : '#10b981'}
          subtitle={suspiciousDnsCount > 0 ? 'High length/entropy' : 'Nominal DNS activity'}
        />
      </div>

      {/* Top Queried Domains Chart */}
      {topDomainList.length > 0 && (
        <Card>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>
            Most Queried Domain Names
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={topDomainList} layout="vertical" margin={{ left: 80, right: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} stroke="var(--border)" />
              <YAxis
                dataKey="domain"
                type="category"
                tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontFamily: 'JetBrains Mono' }}
                stroke="var(--border)"
                width={120}
              />
              <Tooltip
                contentStyle={{
                  background: '#0f172a',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  fontSize: 11.5,
                  fontFamily: 'JetBrains Mono',
                }}
                formatter={(val: any) => [val, 'Queries']}
              />
              <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} barSize={16} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}

      {/* Search Bar */}
      <Card>
        <div style={{ position: 'relative' }}>
          <Search
            size={13}
            style={{
              position: 'absolute',
              left: 10,
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--text-muted)',
            }}
          />
          <input
            className="soc-input"
            style={{ paddingLeft: 30 }}
            placeholder="Filter DNS records by domain name, query type, or client IP..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
        </div>
      </Card>

      {/* Main DNS Table */}
      <Card style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={30} />
          </div>
        ) : records.length === 0 ? (
          <EmptyState
            icon={<Globe size={40} />}
            title="No DNS Records Found"
            message="No DNS query packets match your search parameters."
          />
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 140 }}>Timestamp</th>
                  <th style={{ width: 150 }}>Client (Source)</th>
                  <th style={{ width: 150 }}>DNS Server</th>
                  <th>Queried Domain Name</th>
                  <th style={{ width: 85 }}>Type</th>
                  <th style={{ width: 100 }}>Response</th>
                  <th>Resolved IP / Address</th>
                  <th style={{ width: 75 }}>TTL</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.id}>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10.5, color: 'var(--text-muted)' }}>
                      {r.timestamp_str || String(r.timestamp)}
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--accent)' }}>
                        {r.src_ip || '—'}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--text-primary)' }}>
                        {r.dst_ip || '—'}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: 'JetBrains Mono',
                          fontSize: 12,
                          color: 'var(--text-primary)',
                          fontWeight: 600,
                          wordBreak: 'break-all',
                        }}
                      >
                        {r.query_name || '—'}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          padding: '1px 6px',
                          borderRadius: 3,
                          background: 'rgba(56, 189, 248, 0.14)',
                          color: '#38bdf8',
                          fontFamily: 'JetBrains Mono',
                          fontSize: 10.5,
                          fontWeight: 700,
                        }}
                      >
                        {r.query_type || 'A'}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontSize: 11,
                          fontWeight: 600,
                          fontFamily: 'JetBrains Mono',
                          color: r.response_code === 'NOERROR' || r.is_response ? 'var(--success)' : 'var(--text-muted)',
                        }}
                      >
                        {r.is_response ? r.response_code || 'RESP' : 'QUERY'}
                      </span>
                    </td>
                    <td>
                      {r.response_ips && r.response_ips.length > 0 ? (
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {r.response_ips.slice(0, 3).map((ip) => (
                            <span
                              key={ip}
                              style={{
                                fontFamily: 'JetBrains Mono',
                                fontSize: 11,
                                color: '#34d399',
                                background: 'rgba(16, 185, 129, 0.1)',
                                padding: '1px 5px',
                                borderRadius: 3,
                              }}
                            >
                              {ip}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>—</span>
                      )}
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                      {r.ttl !== null ? `${r.ttl}s` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

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

export default DNS;
