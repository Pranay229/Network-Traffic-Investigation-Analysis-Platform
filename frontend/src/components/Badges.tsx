import React from 'react';
import type { AlertSeverity, AlertStatus, HostRole, UserRole } from '../types';

interface SeverityBadgeProps {
  severity: AlertSeverity | string;
  size?: 'sm' | 'md';
}

const SEV_CONFIG: Record<string, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: 'CRITICAL', color: '#f87171', bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.4)' },
  high: { label: 'HIGH', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.12)', border: 'rgba(239, 68, 68, 0.35)' },
  medium: { label: 'MEDIUM', color: '#f97316', bg: 'rgba(249, 115, 22, 0.12)', border: 'rgba(249, 115, 22, 0.35)' },
  low: { label: 'LOW', color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.12)', border: 'rgba(245, 158, 11, 0.35)' },
  informational: { label: 'INFO', color: '#06b6d4', bg: 'rgba(6, 182, 212, 0.12)', border: 'rgba(6, 182, 212, 0.35)' },
  info: { label: 'INFO', color: '#06b6d4', bg: 'rgba(6, 182, 212, 0.12)', border: 'rgba(6, 182, 212, 0.35)' },
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const sevKey = (severity || 'info').toLowerCase();
  const c = SEV_CONFIG[sevKey] || SEV_CONFIG.informational;
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: size === 'sm' ? '1px 5px' : '2px 8px',
        borderRadius: 4,
        fontSize: size === 'sm' ? 10 : 11,
        fontWeight: 700,
        letterSpacing: '0.04em',
        fontFamily: 'JetBrains Mono, monospace',
        color: c.color,
        background: c.bg,
        border: `1px solid ${c.border}`,
        lineHeight: 1.2,
      }}
    >
      {c.label}
    </span>
  );
};

interface StatusBadgeProps {
  status: AlertStatus | string;
}

const STATUS_CONFIG: Record<string, { color: string; bg: string; dot: string; border: string }> = {
  new: { color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.12)', dot: '#38bdf8', border: 'rgba(56, 189, 248, 0.25)' },
  investigating: { color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.12)', dot: '#fbbf24', border: 'rgba(251, 191, 36, 0.25)' },
  resolved: { color: '#34d399', bg: 'rgba(52, 211, 153, 0.12)', dot: '#34d399', border: 'rgba(52, 211, 153, 0.25)' },
  pending: { color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.12)', dot: '#94a3b8', border: 'rgba(148, 163, 184, 0.25)' },
  processing: { color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.12)', dot: '#fbbf24', border: 'rgba(251, 191, 36, 0.25)' },
  analyzing: { color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.12)', dot: '#38bdf8', border: 'rgba(56, 189, 248, 0.25)' },
  completed: { color: '#34d399', bg: 'rgba(52, 211, 153, 0.12)', dot: '#34d399', border: 'rgba(52, 211, 153, 0.25)' },
  failed: { color: '#f87171', bg: 'rgba(248, 113, 113, 0.12)', dot: '#f87171', border: 'rgba(248, 113, 113, 0.25)' },
};

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const sKey = (status || 'pending').toLowerCase();
  const c = STATUS_CONFIG[sKey] || STATUS_CONFIG.pending;
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        padding: '2px 8px',
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 600,
        fontFamily: 'JetBrains Mono, monospace',
        color: c.color,
        background: c.bg,
        border: `1px solid ${c.border}`,
        lineHeight: 1.2,
      }}
    >
      <span className="pulse-dot" style={{ background: c.dot }} />
      {status.toUpperCase()}
    </span>
  );
};

export const ProtoChip: React.FC<{ protocol: string }> = ({ protocol }) => {
  const p = (protocol || 'OTHER').toUpperCase();
  const cls = ['TCP', 'UDP', 'DNS', 'HTTP', 'ICMP', 'ARP', 'TLS'].includes(p)
    ? `proto-${p.toLowerCase()}`
    : 'proto-other';
  return <span className={`proto-chip ${cls}`}>{p}</span>;
};

export const RoleBadge: React.FC<{ role: HostRole | UserRole | string }> = ({ role }) => {
  const r = (role || 'unknown').toLowerCase();
  const colors: Record<string, { color: string; bg: string; border: string }> = {
    admin: { color: '#c084fc', bg: 'rgba(192, 132, 252, 0.15)', border: 'rgba(192, 132, 252, 0.3)' },
    analyst: { color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.15)', border: 'rgba(56, 189, 248, 0.3)' },
    viewer: { color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.15)', border: 'rgba(148, 163, 184, 0.3)' },
    server: { color: '#34d399', bg: 'rgba(52, 211, 153, 0.15)', border: 'rgba(52, 211, 153, 0.3)' },
    client: { color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.15)', border: 'rgba(56, 189, 248, 0.3)' },
    gateway: { color: '#fb923c', bg: 'rgba(251, 146, 60, 0.15)', border: 'rgba(251, 146, 60, 0.3)' },
    unknown: { color: '#64748b', bg: 'rgba(100, 116, 139, 0.15)', border: 'rgba(100, 116, 139, 0.3)' },
  };

  const c = colors[r] || colors.unknown;
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '1px 7px',
        borderRadius: 4,
        fontSize: 10.5,
        fontWeight: 600,
        fontFamily: 'JetBrains Mono, monospace',
        color: c.color,
        background: c.bg,
        border: `1px solid ${c.border}`,
      }}
    >
      {role.toUpperCase()}
    </span>
  );
};

export const MethodBadge: React.FC<{ method: string }> = ({ method }) => {
  const m = (method || 'GET').toUpperCase();
  const cls = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(m)
    ? `method-${m.toLowerCase()}`
    : 'method-get';
  return <span className={`method-badge ${cls}`}>{m}</span>;
};
