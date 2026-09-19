import React, { useState, useEffect } from 'react';
import { Crosshair, Search, Copy, Check, RefreshCw } from 'lucide-react';
import { SectionHeader, Card, EmptyState, LoadingSpinner, Pagination } from '../components/UI';
import { getIOCs } from '../services/api';
import type { IOC } from '../types';

export const IOCExplorer: React.FC = () => {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
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
      const res = await getIOCs(invId, {
        ioc_type: typeFilter === 'all' ? undefined : typeFilter,
        search: search || undefined,
        page,
      });
      setIocs(res.iocs);
      setTotal(res.total);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId, typeFilter, search, page]);

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="IOC Explorer"
          subtitle="Indicators of Compromise & Suspicious Artifact Extraction"
          icon={<Crosshair size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Crosshair size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to extract Indicators of Compromise (IOCs) such as external IPs, queried domains, and suspicious ports."
          />
        </Card>
      </div>
    );
  }

  const getTypeBadgeStyle = (t: string) => {
    switch (t) {
      case 'ipv4':
      case 'ipv6':
        return { bg: 'rgba(6, 182, 212, 0.12)', color: '#06b6d4', border: 'rgba(6, 182, 212, 0.3)' };
      case 'domain':
        return { bg: 'rgba(16, 185, 129, 0.12)', color: '#34d399', border: 'rgba(16, 185, 129, 0.3)' };
      case 'url':
        return { bg: 'rgba(59, 130, 246, 0.12)', color: '#60a5fa', border: 'rgba(59, 130, 246, 0.3)' };
      case 'port':
        return { bg: 'rgba(245, 158, 11, 0.12)', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.3)' };
      default:
        return { bg: 'rgba(139, 92, 246, 0.12)', color: '#a78bfa', border: 'rgba(139, 92, 246, 0.3)' };
    }
  };

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="IOC Explorer"
        subtitle={`${total.toLocaleString()} Indicators of Interest & network artifacts identified`}
        icon={<Crosshair size={18} />}
        actions={
          <button className="btn-ghost" onClick={loadData} style={{ fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        }
      />

      {/* Category Filter Chips */}
      <Card>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
          {[
            { id: 'all', label: 'All Indicators' },
            { id: 'ipv4', label: 'IPv4 Addresses' },
            { id: 'ipv6', label: 'IPv6 Addresses' },
            { id: 'domain', label: 'Domains' },
            { id: 'url', label: 'URLs' },
            { id: 'port', label: 'Target Ports' },
            { id: 'user_agent', label: 'User Agents' },
          ].map((c) => {
            const isActive = typeFilter === c.id;
            return (
              <button
                key={c.id}
                onClick={() => {
                  setTypeFilter(c.id);
                  setPage(1);
                }}
                className={isActive ? 'btn-primary' : 'btn-ghost'}
                style={{ fontSize: 11.5, padding: '5px 12px' }}
              >
                {c.label}
              </button>
            );
          })}
        </div>

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
            placeholder="Search indicator values, source context, or artifacts..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
        </div>
      </Card>

      {/* IOC Records Table */}
      <Card style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={30} />
          </div>
        ) : iocs.length === 0 ? (
          <EmptyState
            icon={<Crosshair size={40} />}
            title="No Indicators Found"
            message="No indicators match the selected filters."
          />
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 110 }}>Type</th>
                  <th>Indicator Value</th>
                  <th style={{ width: 100 }}>Occurrences</th>
                  <th style={{ width: 150 }}>Source Host Context</th>
                  <th style={{ width: 130 }}>First Seen</th>
                  <th style={{ width: 130 }}>Last Seen</th>
                  <th style={{ width: 80 }}>Copy</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => {
                  const bStyle = getTypeBadgeStyle(ioc.type);
                  const isCopied = copiedValue === ioc.value;
                  return (
                    <tr key={ioc.id}>
                      <td>
                        <span
                          style={{
                            padding: '2px 7px',
                            borderRadius: 4,
                            background: bStyle.bg,
                            color: bStyle.color,
                            border: `1px solid ${bStyle.border}`,
                            fontFamily: 'JetBrains Mono',
                            fontSize: 10.5,
                            fontWeight: 700,
                            textTransform: 'uppercase',
                          }}
                        >
                          {ioc.type}
                        </span>
                      </td>
                      <td>
                        <span
                          style={{
                            fontFamily: 'JetBrains Mono',
                            fontSize: 12,
                            fontWeight: 600,
                            color: 'var(--text-primary)',
                            wordBreak: 'break-all',
                          }}
                        >
                          {ioc.value}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                        {ioc.occurrences.toLocaleString()}
                      </td>
                      <td>
                        <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--accent)' }}>
                          {ioc.source_ip || ioc.context || '—'}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10.5, color: 'var(--text-muted)' }}>
                        {ioc.first_seen?.slice(0, 19) || '—'}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10.5, color: 'var(--text-muted)' }}>
                        {ioc.last_seen?.slice(0, 19) || '—'}
                      </td>
                      <td>
                        <button
                          className="btn-ghost"
                          style={{ padding: '3px 8px', fontSize: 11 }}
                          onClick={() => handleCopy(ioc.value)}
                          title="Copy IOC to clipboard"
                        >
                          {isCopied ? <Check size={12} color="var(--success)" /> : <Copy size={12} />}
                        </button>
                      </td>
                    </tr>
                  );
                })}
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

export default IOCExplorer;
