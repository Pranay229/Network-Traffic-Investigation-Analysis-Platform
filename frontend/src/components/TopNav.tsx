import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Shield, ChevronDown, AlertCircle, RefreshCw, Search, Menu
} from 'lucide-react';
import { StatusBadge } from './Badges';
import { LoadingSpinner } from './UI';
import { GlobalSearchModal } from './GlobalSearchModal';
import type { Investigation } from '../types';
import { getInvestigations, checkHealth } from '../services/api';

interface TopNavProps {
  onMobileMenuToggle?: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({ onMobileMenuToggle }) => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selected, setSelected] = useState<Investigation | null>(null);
  const [dropOpen, setDropOpen] = useState(false);
  const [searchModalOpen, setSearchModalOpen] = useState(false);
  const [backendOk, setBackendOk] = useState<boolean | null>(null);

  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    fetchInvestigations();
    checkBackend();
    const id = setInterval(checkBackend, 15000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setSearchModalOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    const saved = localStorage.getItem('selected_inv');
    const list = Array.isArray(investigations) ? investigations : [];
    if (saved && list.length > 0) {
      const inv = list.find((i) => i.inv_id === saved);
      if (inv) setSelected(inv);
    } else if (!saved && list.length > 0) {
      setSelected(list[0]);
      localStorage.setItem('selected_inv', list[0].inv_id);
    }
  }, [investigations]);

  const fetchInvestigations = async () => {
    try {
      const data = await getInvestigations();
      setInvestigations(Array.isArray(data) ? data : []);
    } catch {
      setInvestigations([]);
    }
  };

  const checkBackend = async () => {
    try {
      const res = await checkHealth();
      setBackendOk(Boolean(res && (res.status === 'ok' || res.status === 'healthy')));
    } catch {
      setBackendOk(false);
    }
  };

  const selectInvestigation = (inv: Investigation) => {
    setSelected(inv);
    localStorage.setItem('selected_inv', inv.inv_id);
    setDropOpen(false);
    navigate('/');
  };

  const pathParts = location.pathname.split('/').filter(Boolean);
  const pageTitle = pathParts.length > 0
    ? pathParts[0].charAt(0).toUpperCase() + pathParts[0].slice(1).replace('-', ' ')
    : 'Overview';

  return (
    <>
      <header
        style={{
          height: 52,
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 16px',
          flexShrink: 0,
          position: 'sticky',
          top: 0,
          zIndex: 40,
        }}
      >
        {/* Left Side: Mobile Menu Button & Breadcrumb */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {onMobileMenuToggle && (
            <button
              onClick={onMobileMenuToggle}
              className="md:hidden"
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                padding: 4,
              }}
            >
              <Menu size={18} />
            </button>
          )}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 12,
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            <span style={{ color: 'var(--text-dim)' }}>NTI</span>
            <span style={{ color: 'var(--border-hover)' }}>/</span>
            <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{pageTitle}</span>
            {selected && (
              <>
                <span style={{ color: 'var(--border-hover)' }}>/</span>
                <span style={{ color: 'var(--accent)', fontSize: 11 }}>{selected.inv_id}</span>
              </>
            )}
          </div>
        </div>

        {/* Center: Quick Global Search Bar */}
        <div
          onClick={() => setSearchModalOpen(true)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            padding: '5px 12px',
            cursor: 'pointer',
            minWidth: 260,
            maxWidth: 360,
            color: 'var(--text-dim)',
            transition: 'border-color 0.15s',
          }}
          className="hidden sm:flex"
        >
          <Search size={13} color="var(--text-dim)" />
          <span style={{ fontSize: 11.5, flex: 1 }}>Search IPs, alerts, IOCs...</span>
          <span
            style={{
              fontSize: 9.5,
              fontFamily: 'JetBrains Mono',
              padding: '1px 5px',
              borderRadius: 3,
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border)',
              color: 'var(--text-dim)',
            }}
          >
            Ctrl+K
          </span>
        </div>

        {/* Right Side: Investigation Selector & System Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {/* Investigation selector */}
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => {
                setDropOpen((o) => !o);
                fetchInvestigations();
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                background: 'var(--bg-card)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: '5px 10px',
                cursor: 'pointer',
                color: 'var(--text-primary)',
                fontSize: 11.5,
                fontWeight: 500,
                maxWidth: 240,
              }}
            >
              <Shield size={13} color="var(--accent)" />
              <span
                style={{
                  flex: 1,
                  textAlign: 'left',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  fontFamily: 'JetBrains Mono',
                }}
              >
                {selected ? selected.inv_id : 'Select Inv'}
              </span>
              {selected && <StatusBadge status={selected.status} />}
              <ChevronDown size={12} color="var(--text-muted)" />
            </button>

            {dropOpen && (
              <div
                style={{
                  position: 'absolute',
                  top: '100%',
                  right: 0,
                  marginTop: 4,
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  borderRadius: 8,
                  zIndex: 100,
                  minWidth: 320,
                  boxShadow: '0 10px 30px rgba(0,0,0,0.5)',
                  maxHeight: 320,
                  overflowY: 'auto',
                }}
              >
                <div
                  style={{
                    padding: '8px 12px',
                    borderBottom: '1px solid var(--border)',
                    fontSize: 10.5,
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    color: 'var(--text-muted)',
                    fontFamily: 'JetBrains Mono',
                  }}
                >
                  Active Investigations
                </div>
                {(!Array.isArray(investigations) || investigations.length === 0) ? (
                  <div style={{ padding: 16, fontSize: 12, color: 'var(--text-muted)', textAlign: 'center' }}>
                    No investigations found.<br />
                    <span
                      style={{ color: 'var(--accent)', cursor: 'pointer', fontWeight: 600 }}
                      onClick={() => {
                        navigate('/upload');
                        setDropOpen(false);
                      }}
                    >
                      Upload a PCAP to start
                    </span>
                  </div>
                ) : (
                  investigations.map((inv) => (
                    <div
                      key={inv.inv_id}
                      onClick={() => selectInvestigation(inv)}
                      style={{
                        padding: '9px 12px',
                        cursor: 'pointer',
                        borderBottom: '1px solid var(--border-subtle)',
                        background: selected?.inv_id === inv.inv_id ? 'rgba(6,182,212,0.1)' : 'transparent',
                        transition: 'background 0.15s',
                      }}
                      onMouseEnter={(e) => {
                        if (selected?.inv_id !== inv.inv_id) {
                          (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.03)';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (selected?.inv_id !== inv.inv_id) {
                          (e.currentTarget as HTMLElement).style.background = 'transparent';
                        }
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                        <span style={{ fontSize: 11.5, fontWeight: 700, fontFamily: 'JetBrains Mono', color: 'var(--accent)' }}>
                          {inv.inv_id}
                        </span>
                        <StatusBadge status={inv.status} />
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {inv.filename} · {inv.total_packets.toLocaleString()} pkts · {inv.total_alerts} alerts
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>

          {/* Refresh Action */}
          <button
            className="btn-ghost"
            style={{ padding: '5px 8px' }}
            onClick={fetchInvestigations}
            title="Refresh Investigations"
          >
            <RefreshCw size={12} />
          </button>

          {/* Backend Status Indicator */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              fontSize: 10.5,
              fontWeight: 600,
              fontFamily: 'JetBrains Mono',
              color: backendOk === null ? 'var(--text-muted)' : backendOk ? 'var(--success)' : 'var(--danger)',
              padding: '3px 8px',
              borderRadius: 4,
              background: backendOk === null ? 'transparent' : backendOk ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
              border: `1px solid ${backendOk ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
            }}
            className="hidden sm:flex"
            title={backendOk ? 'API Server connected and healthy' : 'API Server disconnected'}
          >
            {backendOk === null ? (
              <LoadingSpinner size={10} />
            ) : backendOk ? (
              <span className="pulse-dot" style={{ background: '#10b981' }} />
            ) : (
              <AlertCircle size={10} />
            )}
            <span>{backendOk === null ? 'Checking' : backendOk ? 'LIVE' : 'OFFLINE'}</span>
          </div>

          {/* SOC Console Badge */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '4px 10px',
              borderRadius: 6,
              background: 'rgba(6, 182, 212, 0.1)',
              border: '1px solid rgba(6, 182, 212, 0.25)',
              color: 'var(--accent)',
              fontSize: 11,
              fontWeight: 600,
              fontFamily: 'JetBrains Mono, monospace',
              letterSpacing: '0.02em',
            }}
            title="Operator Mode: Open Investigation Console"
          >
            <Shield size={12} color="var(--accent)" />
            <span>SOC CONSOLE</span>
          </div>
        </div>

        {/* Click outside to close */}
        {dropOpen && (
          <div
            style={{ position: 'fixed', inset: 0, zIndex: 35 }}
            onClick={() => {
              setDropOpen(false);
            }}
          />
        )}
      </header>

      {/* Global Search Modal */}
      <GlobalSearchModal
        isOpen={searchModalOpen}
        onClose={() => setSearchModalOpen(false)}
      />
    </>
  );
};

export default TopNav;
