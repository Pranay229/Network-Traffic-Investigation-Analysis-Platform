import React, { useState, useEffect } from 'react';
import { AlertTriangle, Info, CheckCircle2, Search, RefreshCw } from 'lucide-react';
import { SectionHeader, Card, KPICard, EmptyState, LoadingSpinner, Drawer } from '../components/UI';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { getAlerts, updateAlertStatus } from '../services/api';
import type { Alert, AlertSeverity } from '../types';

const SEV_ORDER: AlertSeverity[] = ['high', 'medium', 'low', 'informational'];

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [sevFilter, setSevFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');

  const invId = localStorage.getItem('selected_inv') || '';

  const loadAlerts = async () => {
    if (!invId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data = await getAlerts(invId, {
        severity: sevFilter || undefined,
        status: statusFilter || undefined,
      });
      setAlerts(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [invId, sevFilter, statusFilter]);

  const handleStatusChange = async (status: string) => {
    if (!selected || !invId) return;
    try {
      await updateAlertStatus(invId, selected.alert_id, status);
      setSelected((prev) => (prev ? { ...prev, status: status as any } : null));
      loadAlerts();
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Security Alerts"
          subtitle="Heuristic anomaly detections and threat event evaluation"
          icon={<AlertTriangle size={18} />}
        />
        <Card>
          <EmptyState
            icon={<AlertTriangle size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to triage detected network anomalies and suspicious events."
          />
        </Card>
      </div>
    );
  }

  const filteredAlerts = alerts.filter((a) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      a.alert_id.toLowerCase().includes(q) ||
      a.alert_type.toLowerCase().includes(q) ||
      (a.src_ip && a.src_ip.toLowerCase().includes(q)) ||
      (a.dst_ip && a.dst_ip.toLowerCase().includes(q)) ||
      (a.detection_rule && a.detection_rule.toLowerCase().includes(q))
    );
  });

  const highCount = alerts.filter((a) => a.severity === 'high').length;
  const medCount = alerts.filter((a) => a.severity === 'medium').length;
  const lowCount = alerts.filter((a) => a.severity === 'low').length;
  const infoCount = alerts.filter((a) => a.severity === 'informational').length;

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="Security Alerts"
        subtitle={`${alerts.length} anomalous pattern${alerts.length !== 1 ? 's' : ''} detected across packet flows`}
        icon={<AlertTriangle size={18} />}
        actions={
          <button className="btn-ghost" onClick={loadAlerts} style={{ fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        }
      />

      {/* Severity Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
        <div
          onClick={() => setSevFilter(sevFilter === 'high' ? '' : 'high')}
          style={{ cursor: 'pointer' }}
        >
          <KPICard
            label="High Severity"
            value={highCount}
            icon={<AlertTriangle size={18} />}
            color="#ef4444"
            subtitle={sevFilter === 'high' ? 'Active Filter' : 'Click to filter'}
          />
        </div>
        <div
          onClick={() => setSevFilter(sevFilter === 'medium' ? '' : 'medium')}
          style={{ cursor: 'pointer' }}
        >
          <KPICard
            label="Medium Severity"
            value={medCount}
            icon={<AlertTriangle size={18} />}
            color="#f97316"
            subtitle={sevFilter === 'medium' ? 'Active Filter' : 'Click to filter'}
          />
        </div>
        <div
          onClick={() => setSevFilter(sevFilter === 'low' ? '' : 'low')}
          style={{ cursor: 'pointer' }}
        >
          <KPICard
            label="Low Severity"
            value={lowCount}
            icon={<AlertTriangle size={18} />}
            color="#f59e0b"
            subtitle={sevFilter === 'low' ? 'Active Filter' : 'Click to filter'}
          />
        </div>
        <div
          onClick={() => setSevFilter(sevFilter === 'informational' ? '' : 'informational')}
          style={{ cursor: 'pointer' }}
        >
          <KPICard
            label="Informational"
            value={infoCount}
            icon={<Info size={18} />}
            color="#06b6d4"
            subtitle={sevFilter === 'informational' ? 'Active Filter' : 'Click to filter'}
          />
        </div>
      </div>

      {/* Heuristic Notice Banner */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 10,
          padding: '12px 14px',
          background: 'rgba(245, 158, 11, 0.08)',
          border: '1px solid rgba(245, 158, 11, 0.25)',
          borderRadius: 8,
          fontSize: 12,
          color: '#fbbf24',
        }}
      >
        <Info size={15} className="shrink-0 mt-0.5" />
        <div>
          <strong>Automated Heuristic Detection Notice:</strong> Alerts are generated via pattern analysis rules. False positives may occur during standard benign network scans. SOC Analyst confirmation is required prior to taking mitigation actions.
        </div>
      </div>

      {/* Filter Toolbar */}
      <Card>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              Severity
            </label>
            <select
              className="soc-input"
              style={{ width: 140 }}
              value={sevFilter}
              onChange={(e) => setSevFilter(e.target.value)}
            >
              <option value="">All Severities</option>
              {SEV_ORDER.map((s) => (
                <option key={s} value={s}>
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              Status
            </label>
            <select
              className="soc-input"
              style={{ width: 140 }}
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>

          <div style={{ flex: 1, minWidth: 180 }}>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
              Search Alerts
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
                placeholder="Search rule, IP, type, or alert ID..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>

          <button
            className="btn-ghost"
            style={{ fontSize: 12 }}
            onClick={() => {
              setSevFilter('');
              setStatusFilter('');
              setSearch('');
            }}
          >
            Clear Filters
          </button>
        </div>
      </Card>

      {/* Alerts Table */}
      <Card style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={30} />
          </div>
        ) : filteredAlerts.length === 0 ? (
          <EmptyState
            icon={<CheckCircle2 size={40} />}
            title="No Alerts Found"
            message={
              alerts.length === 0
                ? 'No anomalous network behavior was detected in this capture.'
                : 'No alerts match the active filter parameters.'
            }
          />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 130 }}>Alert ID</th>
                <th style={{ width: 110 }}>Severity</th>
                <th>Alert Event / Rule Name</th>
                <th style={{ width: 150 }}>Source IP</th>
                <th style={{ width: 150 }}>Destination IP</th>
                <th style={{ width: 140 }}>First Detected</th>
                <th style={{ width: 120 }}>Triage Status</th>
                <th style={{ width: 90 }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((a) => (
                <tr
                  key={a.alert_id}
                  style={{ cursor: 'pointer' }}
                  onClick={() => setSelected(a)}
                >
                  <td>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--text-muted)' }}>
                      {a.alert_id}
                    </span>
                  </td>
                  <td>
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td>
                    <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-primary)' }}>
                      {a.alert_type}
                    </div>
                    {a.detection_rule && (
                      <div style={{ fontSize: 10.5, color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                        Rule: {a.detection_rule}
                      </div>
                    )}
                  </td>
                  <td>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--accent)' }}>
                      {a.src_ip || '—'}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11.5, color: 'var(--text-primary)' }}>
                      {a.dst_ip || '—'}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                    {a.first_seen_str || '—'}
                  </td>
                  <td>
                    <StatusBadge status={a.status} />
                  </td>
                  <td>
                    <button
                      className="btn-ghost"
                      style={{ fontSize: 11, padding: '3px 8px' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelected(a);
                      }}
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* Alert Investigation Slide-Over Drawer */}
      <Drawer
        isOpen={!!selected}
        onClose={() => setSelected(null)}
        title={selected?.alert_type || 'Alert Investigation'}
        subtitle={`Alert ID: ${selected?.alert_id || ''}`}
        width={600}
      >
        {selected && (
          <div className="space-y-4">
            {/* Header Status & Severity */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <SeverityBadge severity={selected.severity} />
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>{selected.alert_id}</span>
              </div>
              <StatusBadge status={selected.status} />
            </div>

            {/* What Happened Section */}
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
              <div style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 6, letterSpacing: '0.04em' }}>
                What Happened?
              </div>
              <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {selected.reason || 'Heuristic threat rule conditions matched against observed packet flows.'}
              </p>
            </div>

            {/* Evidence & Telemetry */}
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
              <div style={{ fontSize: 11.5, fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                Observed Evidence
              </div>
              <div style={{ background: '#070b14', border: '1px solid var(--border-subtle)', borderRadius: 4, padding: 10, fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--text-secondary)' }}>
                {Object.entries(selected.evidence || {}).map(([k, v]) => (
                  <div key={k} style={{ marginBottom: 4 }}>
                    <span style={{ color: 'var(--accent)', fontWeight: 600 }}>{k}</span>: {JSON.stringify(v)}
                  </div>
                ))}
              </div>
            </div>

            {/* Flow Context */}
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
              <div style={{ fontSize: 11.5, fontWeight: 700, color: '#a78bfa', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                Threat Vectors
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 12 }}>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Source IP</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--accent)', fontWeight: 600 }}>{selected.src_ip || '—'}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Destination IP</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600 }}>{selected.dst_ip || '—'}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Protocol</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>{selected.protocol || '—'}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Detection Rule</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>{selected.detection_rule || '—'}</div>
                </div>
              </div>
            </div>

            {/* Recommended Steps */}
            {selected.recommendations && (
              <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
                <div style={{ fontSize: 11.5, fontWeight: 700, color: '#34d399', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                  Recommended Investigation & Triage Steps
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                  {selected.recommendations.split('\n').map((step, i) => (
                    <div key={i} style={{ marginBottom: 3 }}>
                      {step}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Status Update Actions */}
            <div style={{ paddingTop: 10, borderTop: '1px solid var(--border)', display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>Update Status:</span>
              {(['new', 'investigating', 'resolved'] as const).map((s) => (
                <button
                  key={s}
                  className={selected.status === s ? 'btn-primary' : 'btn-ghost'}
                  style={{ fontSize: 11.5, padding: '5px 12px' }}
                  onClick={() => handleStatusChange(s)}
                >
                  {s.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};

export default AlertsPage;
