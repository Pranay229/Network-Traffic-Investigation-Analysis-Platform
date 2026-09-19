import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, X, ArrowRight, AlertTriangle, Globe, FolderOpen, Monitor } from 'lucide-react';
import { getInvestigations, getAlerts, getHosts, getDNS } from '../services/api';
import type { Investigation, Alert, Host, DNSRecord } from '../types';

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const GlobalSearchModal: React.FC<GlobalSearchModalProps> = ({ isOpen, onClose }) => {
  const [query, setQuery] = useState('');
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [dnsRecords, setDnsRecords] = useState<DNSRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const invId = localStorage.getItem('selected_inv') || '';

  useEffect(() => {
    if (!isOpen) {
      setQuery('');
      return;
    }

    const loadContext = async () => {
      setLoading(true);
      try {
        const invs = await getInvestigations();
        setInvestigations(invs);
        if (invId) {
          const [alts, hsts, dns] = await Promise.all([
            getAlerts(invId).catch(() => []),
            getHosts(invId).catch(() => ({ hosts: [], total: 0 })),
            getDNS(invId).catch(() => ({ records: [], total: 0, summary: {} })),
          ]);
          setAlerts(alts);
          setHosts(hsts.hosts);
          setDnsRecords(dns.records);
        }
      } finally {
        setLoading(false);
      }
    };

    loadContext();
  }, [isOpen, invId]);

  if (!isOpen) return null;

  const q = query.trim().toLowerCase();

  // Filtered results
  const matchingInvs = q
    ? investigations.filter(
        (i) =>
          i.inv_id.toLowerCase().includes(q) ||
          i.filename.toLowerCase().includes(q)
      )
    : investigations.slice(0, 3);

  const matchingHosts = q
    ? hosts.filter((h) => h.ip_address.toLowerCase().includes(q))
    : hosts.slice(0, 3);

  const matchingAlerts = q
    ? alerts.filter(
        (a) =>
          a.alert_id.toLowerCase().includes(q) ||
          a.alert_type.toLowerCase().includes(q) ||
          (a.src_ip && a.src_ip.toLowerCase().includes(q)) ||
          (a.dst_ip && a.dst_ip.toLowerCase().includes(q))
      )
    : alerts.slice(0, 3);

  const matchingDNS = q
    ? dnsRecords.filter((d) => d.query_name && d.query_name.toLowerCase().includes(q))
    : [];

  const handleSelectInv = (selectedInv: Investigation) => {
    localStorage.setItem('selected_inv', selectedInv.inv_id);
    onClose();
    navigate('/');
  };

  const handleNavigate = (path: string) => {
    onClose();
    navigate(path);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content"
        style={{
          maxWidth: 620,
          padding: 0,
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 12,
          overflow: 'hidden',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '14px 18px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-secondary)',
          }}
        >
          <Search size={16} color="var(--accent)" />
          <input
            autoFocus
            type="text"
            placeholder="Search by IP, Domain, Investigation ID, Alert ID..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--text-primary)',
              fontSize: 13.5,
              fontFamily: 'inherit',
            }}
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
              }}
            >
              <X size={14} />
            </button>
          )}
          <span
            style={{
              fontSize: 10,
              fontFamily: 'JetBrains Mono',
              padding: '2px 6px',
              borderRadius: 4,
              background: 'rgba(255, 255, 255, 0.06)',
              color: 'var(--text-muted)',
            }}
          >
            ESC
          </span>
        </div>

        {/* Results Container */}
        <div style={{ maxHeight: 420, overflowY: 'auto', padding: '12px 14px' }}>
          {loading ? (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
              Searching SOC records...
            </div>
          ) : (
            <>
              {/* Investigations */}
              {matchingInvs.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6, paddingLeft: 4 }}>
                    Investigations
                  </div>
                  {matchingInvs.map((inv) => (
                    <div
                      key={inv.inv_id}
                      onClick={() => handleSelectInv(inv)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 10px',
                        borderRadius: 6,
                        cursor: 'pointer',
                        transition: 'background 0.15s',
                        marginBottom: 2,
                      }}
                      onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = 'rgba(6, 182, 212, 0.08)')}
                      onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = 'transparent')}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <FolderOpen size={14} color="var(--accent)" />
                        <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                          {inv.inv_id}
                        </span>
                        <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>{inv.filename}</span>
                      </div>
                      <ArrowRight size={12} color="var(--text-dim)" />
                    </div>
                  ))}
                </div>
              )}

              {/* Hosts */}
              {matchingHosts.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6, paddingLeft: 4 }}>
                    Hosts
                  </div>
                  {matchingHosts.map((h) => (
                    <div
                      key={h.ip_address}
                      onClick={() => handleNavigate('/hosts')}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 10px',
                        borderRadius: 6,
                        cursor: 'pointer',
                        transition: 'background 0.15s',
                        marginBottom: 2,
                      }}
                      onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = 'rgba(6, 182, 212, 0.08)')}
                      onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = 'transparent')}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Monitor size={14} color="#34d399" />
                        <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--accent)' }}>
                          {h.ip_address}
                        </span>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {h.role.toUpperCase()} · {h.total_packets.toLocaleString()} pkts
                        </span>
                      </div>
                      <ArrowRight size={12} color="var(--text-dim)" />
                    </div>
                  ))}
                </div>
              )}

              {/* Alerts */}
              {matchingAlerts.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6, paddingLeft: 4 }}>
                    Security Alerts
                  </div>
                  {matchingAlerts.map((a) => (
                    <div
                      key={a.alert_id}
                      onClick={() => handleNavigate('/alerts')}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 10px',
                        borderRadius: 6,
                        cursor: 'pointer',
                        transition: 'background 0.15s',
                        marginBottom: 2,
                      }}
                      onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = 'rgba(239, 68, 68, 0.08)')}
                      onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = 'transparent')}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <AlertTriangle size={14} color="#f87171" />
                        <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: '#f87171', fontWeight: 600 }}>
                          {a.alert_id}
                        </span>
                        <span style={{ fontSize: 11.5, color: 'var(--text-primary)' }}>{a.alert_type}</span>
                      </div>
                      <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                        {a.src_ip} → {a.dst_ip}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* DNS Queries */}
              {matchingDNS.length > 0 && (
                <div style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6, paddingLeft: 4 }}>
                    DNS Lookups
                  </div>
                  {matchingDNS.slice(0, 4).map((d) => (
                    <div
                      key={d.id}
                      onClick={() => handleNavigate('/dns')}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 10px',
                        borderRadius: 6,
                        cursor: 'pointer',
                        transition: 'background 0.15s',
                        marginBottom: 2,
                      }}
                      onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = 'rgba(6, 182, 212, 0.08)')}
                      onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = 'transparent')}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Globe size={14} color="#38bdf8" />
                        <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--text-primary)' }}>
                          {d.query_name}
                        </span>
                      </div>
                      <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                        {d.query_type}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {q &&
                matchingInvs.length === 0 &&
                matchingHosts.length === 0 &&
                matchingAlerts.length === 0 &&
                matchingDNS.length === 0 && (
                  <div style={{ padding: '32px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                    No matching records found for "{query}".
                  </div>
                )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};
