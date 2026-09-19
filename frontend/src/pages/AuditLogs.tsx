import React, { useEffect, useState } from 'react';
import { ShieldAlert, RefreshCw } from 'lucide-react';
import type { AuditLog } from '../types';
import { getAdminAuditLogs } from '../services/api';
import { SectionHeader, Card, EmptyState, LoadingSpinner } from '../components/UI';

export const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [ipFilter, setIpFilter] = useState('');

  const fetchLogs = async () => {
    setIsLoading(true);
    try {
      const data = await getAdminAuditLogs({
        event_type: eventTypeFilter || undefined,
        ip_address: ipFilter || undefined,
        limit: 100,
      });
      setLogs(data);
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [eventTypeFilter, ipFilter]);

  const getEventBadgeStyle = (type: string) => {
    if (type.includes('FAILURE') || type.includes('LOCKED') || type.includes('DELETED')) {
      return { bg: 'rgba(239, 68, 68, 0.12)', color: '#f87171', border: 'rgba(239, 68, 68, 0.3)' };
    }
    if (type.includes('SUCCESS') || type.includes('VERIFIED')) {
      return { bg: 'rgba(16, 185, 129, 0.12)', color: '#34d399', border: 'rgba(16, 185, 129, 0.3)' };
    }
    if (type.includes('ADMIN') || type.includes('ROLE')) {
      return { bg: 'rgba(192, 132, 252, 0.15)', color: '#c084fc', border: 'rgba(192, 132, 252, 0.3)' };
    }
    return { bg: 'rgba(6, 182, 212, 0.12)', color: '#06b6d4', border: 'rgba(6, 182, 212, 0.3)' };
  };

  return (
    <div className="fade-in space-y-4 max-w-6xl mx-auto">
      <SectionHeader
        title="Security Audit Logs"
        subtitle="Immutable SOC audit trail recording authentication, RBAC authorization, and PCAP actions"
        icon={<ShieldAlert size={18} />}
        actions={
          <button className="btn-ghost" onClick={fetchLogs} style={{ fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        }
      />

      {/* Filters Bar */}
      <Card>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <select
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value)}
            className="soc-input"
            style={{ width: 220, fontFamily: 'JetBrains Mono', fontSize: 11.5 }}
          >
            <option value="">All Event Types</option>
            <option value="AUTH_LOGIN_SUCCESS">AUTH_LOGIN_SUCCESS</option>
            <option value="AUTH_LOGIN_FAILURE">AUTH_LOGIN_FAILURE</option>
            <option value="AUTH_LOGIN_LOCKED">AUTH_LOGIN_LOCKED</option>
            <option value="AUTH_ACCOUNT_LOCKED">AUTH_ACCOUNT_LOCKED</option>
            <option value="AUTH_REGISTER">AUTH_REGISTER</option>
            <option value="AUTH_LOGOUT">AUTH_LOGOUT</option>
            <option value="AUTH_LOGOUT_ALL_DEVICES">AUTH_LOGOUT_ALL_DEVICES</option>
            <option value="AUTH_EMAIL_VERIFIED">AUTH_EMAIL_VERIFIED</option>
            <option value="AUTH_PASSWORD_CHANGED">AUTH_PASSWORD_CHANGED</option>
            <option value="AUTH_PASSWORD_RESET_REQUESTED">AUTH_PASSWORD_RESET_REQUESTED</option>
            <option value="AUTH_PASSWORD_RESET_SUCCESS">AUTH_PASSWORD_RESET_SUCCESS</option>
            <option value="ADMIN_USER_ROLE_CHANGED">ADMIN_USER_ROLE_CHANGED</option>
            <option value="ADMIN_USER_STATUS_CHANGED">ADMIN_USER_STATUS_CHANGED</option>
            <option value="PCAP_UPLOAD">PCAP_UPLOAD</option>
            <option value="INVESTIGATION_DELETED">INVESTIGATION_DELETED</option>
            <option value="REPORT_GENERATION">REPORT_GENERATION</option>
          </select>

          <input
            type="text"
            value={ipFilter}
            onChange={(e) => setIpFilter(e.target.value)}
            placeholder="Filter by IP address..."
            className="soc-input"
            style={{ width: 170, fontFamily: 'JetBrains Mono' }}
          />

          <button
            className="btn-ghost"
            style={{ fontSize: 12 }}
            onClick={() => {
              setEventTypeFilter('');
              setIpFilter('');
            }}
          >
            Clear Filters
          </button>
        </div>
      </Card>

      {/* Audit Log Table */}
      <Card style={{ padding: 0 }}>
        {isLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={30} />
          </div>
        ) : logs.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert size={40} />}
            title="No Audit Logs"
            message="No security audit entries match the current filter parameters."
          />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 160 }}>Timestamp</th>
                <th style={{ width: 220 }}>Security Event Type</th>
                <th style={{ width: 100 }}>User ID</th>
                <th style={{ width: 130 }}>IP Address</th>
                <th style={{ width: 150 }}>Target Resource</th>
                <th>Context Metadata</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => {
                const bStyle = getEventBadgeStyle(log.event_type);
                return (
                  <tr key={log.id}>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td>
                      <span
                        style={{
                          padding: '2px 7px',
                          borderRadius: 4,
                          fontSize: 10.5,
                          fontWeight: 700,
                          fontFamily: 'JetBrains Mono',
                          background: bStyle.bg,
                          color: bStyle.color,
                          border: `1px solid ${bStyle.border}`,
                        }}
                      >
                        {log.event_type}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--text-secondary)' }}>
                      {log.user_id ? `#${log.user_id}` : 'Unauthenticated'}
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--accent)' }}>
                      {log.ip_address || '—'}
                    </td>
                    <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                      {log.resource_type ? `${log.resource_type} (${log.resource_id})` : '—'}
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 10.5, color: 'var(--text-dim)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {log.metadata_json ? JSON.stringify(log.metadata_json) : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
};

export default AuditLogs;
