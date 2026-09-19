import React, { useState, useEffect } from 'react';
import { Server, Search, RefreshCw, Globe, AlertTriangle } from 'lucide-react';
import { SectionHeader, Card, KPICard, EmptyState, LoadingSpinner, Pagination } from '../components/UI';
import { MethodBadge } from '../components/Badges';
import { getHTTP } from '../services/api';
import type { HTTPRecord } from '../types';

export const HTTP: React.FC = () => {
  const [records, setRecords] = useState<HTTPRecord[]>([]);
  const [summary, setSummary] = useState<any>({});
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [filterMethod, setFilterMethod] = useState('');
  const [searchPath, setSearchPath] = useState('');
  const pageSize = 50;

  const invId = localStorage.getItem('selected_inv') || '';

  const loadData = async () => {
    if (!invId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await getHTTP(invId, { page });
      setRecords(res.records);
      setSummary(res.summary || {});
      setTotal(res.total);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId, page]);

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="HTTP Investigation"
          subtitle="Application layer HTTP requests, methods, URIs, and server responses"
          icon={<Server size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Server size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to inspect HTTP request headers and methods."
          />
        </Card>
      </div>
    );
  }

  const filteredRecords = records.filter((r) => {
    if (filterMethod && r.method?.toUpperCase() !== filterMethod) return false;
    if (
      searchPath &&
      !r.uri?.toLowerCase().includes(searchPath.toLowerCase()) &&
      !r.host?.toLowerCase().includes(searchPath.toLowerCase()) &&
      !r.src_ip?.toLowerCase().includes(searchPath.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const getStatusClass = (code: number | null) => {
    if (!code) return 'text-slate-400';
    if (code >= 200 && code < 300) return 'status-2xx';
    if (code >= 300 && code < 400) return 'status-3xx';
    if (code >= 400 && code < 500) return 'status-4xx';
    return 'status-5xx';
  };

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="HTTP Investigation"
        subtitle={`${total.toLocaleString()} decoded HTTP application requests`}
        icon={<Server size={18} />}
        actions={
          <button className="btn-ghost" onClick={loadData} style={{ fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        }
      />

      {/* Top HTTP KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12 }}>
        <KPICard
          label="HTTP Requests"
          value={total}
          icon={<Server size={18} />}
          color="#f59e0b"
          subtitle="Total transactions"
        />
        <KPICard
          label="Unique Hosts"
          value={summary.unique_hosts || 0}
          icon={<Globe size={18} />}
          color="#06b6d4"
          subtitle="Web domains"
        />
        <KPICard
          label="GET Requests"
          value={summary.get_count || 0}
          icon={<Server size={18} />}
          color="#10b981"
          subtitle="Data fetches"
        />
        <KPICard
          label="POST Requests"
          value={summary.post_count || 0}
          icon={<Server size={18} />}
          color="#3b82f6"
          subtitle="Data submissions"
        />
        <KPICard
          label="Client Errors (4xx)"
          value={summary.status_4xx || 0}
          icon={<AlertTriangle size={18} />}
          color="#f59e0b"
          subtitle="Not found / unauthorized"
        />
        <KPICard
          label="Server Errors (5xx)"
          value={summary.status_5xx || 0}
          icon={<AlertTriangle size={18} />}
          color="#ef4444"
          subtitle="Internal server failures"
        />
      </div>

      {/* Filter Bar */}
      <Card>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              HTTP Method
            </label>
            <select
              className="soc-input"
              style={{ width: 120 }}
              value={filterMethod}
              onChange={(e) => setFilterMethod(e.target.value)}
            >
              <option value="">All Methods</option>
              {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>

          <div style={{ flex: 1, minWidth: 200 }}>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              Filter by URI Path or Host
            </label>
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
                placeholder="e.g. /api/login, host.com, etc..."
                value={searchPath}
                onChange={(e) => setSearchPath(e.target.value)}
              />
            </div>
          </div>

          <button
            className="btn-ghost"
            style={{ fontSize: 12 }}
            onClick={() => {
              setFilterMethod('');
              setSearchPath('');
            }}
          >
            Clear Filters
          </button>
        </div>
      </Card>

      {/* HTTP Table */}
      <Card style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={30} />
          </div>
        ) : filteredRecords.length === 0 ? (
          <EmptyState
            icon={<Server size={40} />}
            title="No HTTP Transactions Found"
            message="No HTTP request records match the filter criteria."
          />
        ) : (
          <>
            <table className="data-table" style={{ tableLayout: 'fixed' }}>
              <thead>
                <tr>
                  <th style={{ width: 130 }}>Timestamp</th>
                  <th style={{ width: 150 }}>Client (Source)</th>
                  <th style={{ width: 160 }}>Host Header</th>
                  <th style={{ width: 80 }}>Method</th>
                  <th>URI Resource Path</th>
                  <th style={{ width: 85 }}>Status</th>
                  <th style={{ width: 220 }}>User Agent</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.map((r) => (
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
                      <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--text-primary)', fontWeight: 600 }}>
                        {r.host || '—'}
                      </span>
                    </td>
                    <td>
                      <MethodBadge method={r.method || 'GET'} />
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: 'JetBrains Mono',
                          fontSize: 11.5,
                          color: 'var(--text-primary)',
                          wordBreak: 'break-all',
                        }}
                      >
                        {r.uri || '/'}
                      </span>
                    </td>
                    <td>
                      <span className={`font-mono text-xs ${getStatusClass(r.status_code)}`}>
                        {r.status_code || '—'}
                      </span>
                    </td>
                    <td
                      style={{
                        fontSize: 11,
                        color: 'var(--text-muted)',
                        fontFamily: 'JetBrains Mono',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {r.user_agent || '—'}
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

export default HTTP;
