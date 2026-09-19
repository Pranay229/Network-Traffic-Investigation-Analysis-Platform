import React from 'react';
import { X } from 'lucide-react';

export interface KPICardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color?: string;
  subtitle?: string;
  trend?: string;
  trendPositive?: boolean;
}

export const KPICard: React.FC<KPICardProps> = ({
  label,
  value,
  icon,
  color = '#06b6d4',
  subtitle,
  trend,
  trendPositive,
}) => {
  return (
    <div className="kpi-card" style={{ '--kpi-color': color } as React.CSSProperties}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              fontSize: 10.5,
              fontWeight: 600,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginBottom: 6,
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {label}
          </div>
          <div
            style={{
              fontSize: 24,
              fontWeight: 700,
              color: 'var(--text-primary)',
              lineHeight: 1.1,
              fontFamily: 'JetBrains Mono, monospace',
              letterSpacing: '-0.02em',
            }}
          >
            {typeof value === 'number' ? value.toLocaleString() : value}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 5, flexWrap: 'wrap' }}>
            {trend && (
              <span
                style={{
                  fontSize: 10.5,
                  fontWeight: 600,
                  fontFamily: 'JetBrains Mono, monospace',
                  color: trendPositive ? 'var(--success)' : 'var(--danger)',
                }}
              >
                {trend}
              </span>
            )}
            {subtitle && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {subtitle}
              </span>
            )}
          </div>
        </div>
        <div
          style={{
            width: 36,
            height: 36,
            minWidth: 36,
            borderRadius: 8,
            background: `${color}18`,
            border: `1px solid ${color}30`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: color,
          }}
        >
          {icon}
        </div>
      </div>
    </div>
  );
};

export interface SectionHeaderProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  icon?: React.ReactNode;
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({ title, subtitle, actions, icon }) => (
  <div
    style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginBottom: 20,
      flexWrap: 'wrap',
      gap: 12,
    }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      {icon && (
        <div
          style={{
            width: 36,
            height: 36,
            minWidth: 36,
            background: 'rgba(6, 182, 212, 0.12)',
            border: '1px solid rgba(6, 182, 212, 0.25)',
            borderRadius: 8,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent)',
          }}
        >
          {icon}
        </div>
      )}
      <div>
        <h1
          style={{
            fontSize: 18,
            fontWeight: 700,
            color: 'var(--text-primary)',
            lineHeight: 1.2,
            letterSpacing: '-0.01em',
          }}
        >
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{subtitle}</p>
        )}
      </div>
    </div>
    {actions && <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>{actions}</div>}
  </div>
);

export const Card: React.FC<{
  children: React.ReactNode;
  style?: React.CSSProperties;
  className?: string;
}> = ({ children, style, className }) => (
  <div className={`soc-card ${className || ''}`} style={{ padding: 18, ...style }}>
    {children}
  </div>
);

export const EmptyState: React.FC<{
  icon?: React.ReactNode;
  title: string;
  message: string;
  action?: React.ReactNode;
}> = ({ icon, title, message, action }) => (
  <div
    style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '48px 24px',
      textAlign: 'center',
      color: 'var(--text-muted)',
    }}
  >
    {icon && (
      <div
        style={{
          marginBottom: 16,
          color: 'var(--text-dim)',
          background: 'rgba(255, 255, 255, 0.02)',
          padding: 16,
          borderRadius: '50%',
          border: '1px solid var(--border)',
        }}
      >
        {icon}
      </div>
    )}
    <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 6 }}>
      {title}
    </div>
    <div style={{ fontSize: 12.5, color: 'var(--text-muted)', maxWidth: 360, lineHeight: 1.5, marginBottom: action ? 16 : 0 }}>
      {message}
    </div>
    {action && <div>{action}</div>}
  </div>
);

export const LoadingSpinner: React.FC<{ size?: number }> = ({ size = 20 }) => (
  <div
    style={{
      width: size,
      height: size,
      border: `2px solid var(--border)`,
      borderTop: `2px solid var(--accent)`,
      borderRadius: '50%',
      animation: 'spin 0.7s linear infinite',
      display: 'inline-block',
    }}
  >
    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
  </div>
);

export const SkeletonLoader: React.FC<{
  rows?: number;
  height?: number;
  className?: string;
}> = ({ rows = 4, height = 20, className }) => (
  <div className={`space-y-2.5 ${className || ''}`}>
    {Array.from({ length: rows }).map((_, i) => (
      <div
        key={i}
        className="skeleton-box"
        style={{ height, width: i === rows - 1 ? '70%' : '100%' }}
      />
    ))}
  </div>
);

export interface PaginationProps {
  page: number;
  pages: number;
  total: number;
  pageSize: number;
  onChange: (page: number) => void;
}

export const Pagination: React.FC<PaginationProps> = ({
  page,
  pages,
  total,
  pageSize,
  onChange,
}) => {
  if (pages <= 1 && total <= pageSize) return null;
  const start = Math.max(1, (page - 1) * pageSize + 1);
  const end = Math.min(page * pageSize, total);

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 14px',
        borderTop: '1px solid var(--border)',
        marginTop: 4,
        fontSize: 12,
        flexWrap: 'wrap',
        gap: 8,
      }}
    >
      <span style={{ color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
        Showing {start.toLocaleString()}–{end.toLocaleString()} of {total.toLocaleString()}
      </span>
      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <button
          className="btn-ghost"
          style={{ padding: '4px 10px', fontSize: 11.5 }}
          onClick={() => onChange(page - 1)}
          disabled={page <= 1}
        >
          ← Prev
        </button>
        <span
          style={{
            padding: '4px 8px',
            fontSize: 11.5,
            color: 'var(--text-primary)',
            fontFamily: 'JetBrains Mono, monospace',
          }}
        >
          {page} / {Math.max(1, pages)}
        </span>
        <button
          className="btn-ghost"
          style={{ padding: '4px 10px', fontSize: 11.5 }}
          onClick={() => onChange(page + 1)}
          disabled={page >= pages}
        >
          Next →
        </button>
      </div>
    </div>
  );
};

export const ProgressBar: React.FC<{
  value: number;
  label?: string;
  color?: string;
}> = ({ value, label, color = 'var(--accent)' }) => (
  <div style={{ width: '100%' }}>
    {label && (
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          marginBottom: 6,
          fontSize: 11.5,
        }}
      >
        <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
        <span style={{ color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
          {value}%
        </span>
      </div>
    )}
    <div
      style={{
        height: 5,
        background: 'var(--border)',
        borderRadius: 3,
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          height: '100%',
          width: `${Math.min(100, Math.max(0, value))}%`,
          background: color,
          borderRadius: 3,
          transition: 'width 0.3s ease',
        }}
      />
    </div>
  </div>
);

export const Drawer: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  width?: number | string;
}> = ({ isOpen, onClose, title, subtitle, children, width = 540 }) => {
  if (!isOpen) return null;

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div
        className="drawer-content"
        style={{ maxWidth: width }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            marginBottom: 18,
            paddingBottom: 14,
            borderBottom: '1px solid var(--border)',
          }}
        >
          <div>
            <h2
              style={{
                fontSize: 16,
                fontWeight: 700,
                color: 'var(--text-primary)',
                lineHeight: 1.2,
              }}
            >
              {title}
            </h2>
            {subtitle && (
              <div
                style={{
                  fontSize: 11.5,
                  color: 'var(--text-muted)',
                  fontFamily: 'JetBrains Mono, monospace',
                  marginTop: 3,
                }}
              >
                {subtitle}
              </div>
            )}
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: 4,
              borderRadius: 4,
            }}
          >
            <X size={18} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
};

export const ConfirmModal: React.FC<{
  title: string;
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
  confirmLabel?: string;
  danger?: boolean;
}> = ({
  title,
  message,
  onConfirm,
  onCancel,
  confirmLabel = 'Confirm',
  danger = false,
}) => (
  <div className="modal-overlay" onClick={onCancel}>
    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
      <h3
        style={{
          fontSize: 16,
          fontWeight: 700,
          marginBottom: 10,
          color: 'var(--text-primary)',
        }}
      >
        {title}
      </h3>
      <p
        style={{
          fontSize: 13,
          color: 'var(--text-secondary)',
          marginBottom: 20,
          lineHeight: 1.6,
        }}
      >
        {message}
      </p>
      <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
        <button className="btn-ghost" onClick={onCancel}>
          Cancel
        </button>
        <button
          className={danger ? 'btn-danger' : 'btn-primary'}
          onClick={onConfirm}
        >
          {confirmLabel}
        </button>
      </div>
    </div>
  </div>
);

export const Tabs: React.FC<{
  tabs: Array<{ id: string; label: string; count?: number }>;
  activeTab: string;
  onChange: (tabId: string) => void;
}> = ({ tabs, activeTab, onChange }) => (
  <div
    style={{
      display: 'flex',
      gap: 4,
      borderBottom: '1px solid var(--border)',
      marginBottom: 16,
      overflowX: 'auto',
    }}
  >
    {tabs.map((tab) => {
      const isActive = activeTab === tab.id;
      return (
        <button
          key={tab.id}
          onClick={() => onChange(tab.id)}
          style={{
            padding: '8px 14px',
            fontSize: 12.5,
            fontWeight: isActive ? 600 : 500,
            color: isActive ? 'var(--accent)' : 'var(--text-muted)',
            background: 'transparent',
            border: 'none',
            borderBottom: `2px solid ${isActive ? 'var(--accent)' : 'transparent'}`,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            whiteSpace: 'nowrap',
            transition: 'all 0.15s ease',
          }}
        >
          <span>{tab.label}</span>
          {tab.count !== undefined && (
            <span
              style={{
                fontSize: 10.5,
                fontFamily: 'JetBrains Mono, monospace',
                padding: '1px 6px',
                borderRadius: 10,
                background: isActive ? 'rgba(6, 182, 212, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                color: isActive ? 'var(--accent)' : 'var(--text-dim)',
              }}
            >
              {tab.count}
            </span>
          )}
        </button>
      );
    })}
  </div>
);
