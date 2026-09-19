import React, { useState, useEffect } from 'react';
import { Settings, Sliders, CheckCircle2, Terminal, HardDrive } from 'lucide-react';
import { SectionHeader, Card, LoadingSpinner } from '../components/UI';
import { getSettings, updateSettings } from '../services/api';
import type { Settings as SettingsType } from '../types';

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<SettingsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [saved, setSaved] = useState(false);
  const [form, setForm] = useState<Record<string, number | string>>({});

  useEffect(() => {
    getSettings()
      .then((s) => {
        setSettings(s);
        setForm({
          port_scan_min_ports: s.port_scan_min_ports,
          port_scan_time_window: s.port_scan_time_window,
          dns_query_threshold: s.dns_query_threshold,
          icmp_threshold: s.icmp_threshold,
          tcp_conn_threshold: s.tcp_conn_threshold,
          high_conn_threshold: s.high_conn_threshold,
          long_dns_query_len: s.long_dns_query_len,
          high_subdomain_count: s.high_subdomain_count,
        });
      })
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    try {
      const res = await updateSettings(form);
      setSettings(res);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      console.error('Settings update failed:', e);
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}>
        <LoadingSpinner size={32} />
      </div>
    );
  }

  const DETECTION_FIELDS = [
    { key: 'port_scan_min_ports', label: 'Port Scan Threshold', desc: 'Minimum distinct ports accessed per source to flag port scanning', unit: 'ports' },
    { key: 'port_scan_time_window', label: 'Port Scan Time Window', desc: 'Sliding observation duration for port scan heuristics', unit: 'seconds' },
    { key: 'dns_query_threshold', label: 'DNS Query Rate Limit', desc: 'Maximum queries per second per client before triggering flood alert', unit: 'queries/sec' },
    { key: 'icmp_threshold', label: 'ICMP Anomaly Threshold', desc: 'Total control packets within capture triggering high-volume flag', unit: 'packets' },
    { key: 'tcp_conn_threshold', label: 'TCP SYN Inundation Threshold', desc: 'SYN packets per origin without ACK completion', unit: 'connections' },
    { key: 'high_conn_threshold', label: 'Destination Spread Threshold', desc: 'Unique destination IPs contacted by single client', unit: 'hosts' },
    { key: 'long_dns_query_len', label: 'DNS Tunneling Length', desc: 'Character length of query names suspicious of data exfiltration', unit: 'characters' },
    { key: 'high_subdomain_count', label: 'Subdomain Enumeration Limit', desc: 'Distinct subdomains under parent domain triggering alert', unit: 'subdomains' },
  ];

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="Settings"
        subtitle="Detection heuristics, engine parameters, and platform thresholds"
        icon={<Settings size={18} />}
      />

      {/* Engine & Environment Telemetry */}
      <Card>
        <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>
          Analysis Engine & Telemetry Environment
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
          <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: 10.5, textTransform: 'uppercase', marginBottom: 4 }}>
              <Terminal size={12} /> TShark Dissector Engine
            </div>
            <div style={{ fontSize: 12.5, fontWeight: 600, color: settings?.tshark_available ? 'var(--success)' : 'var(--danger)', fontFamily: 'JetBrains Mono' }}>
              {settings?.tshark_available ? 'Active & Available' : 'Not Found on Host Path'}
            </div>
          </div>

          <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: 10.5, textTransform: 'uppercase', marginBottom: 4 }}>
              <Sliders size={12} /> Executable Binary Path
            </div>
            <div style={{ fontSize: 11.5, fontFamily: 'JetBrains Mono', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {settings?.tshark_path || 'tshark'}
            </div>
          </div>

          <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: 10.5, textTransform: 'uppercase', marginBottom: 4 }}>
              <HardDrive size={12} /> Upload File Size Ceiling
            </div>
            <div style={{ fontSize: 12.5, fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600 }}>
              {settings?.max_upload_size_mb} MB
            </div>
          </div>
        </div>
      </Card>

      {/* Detection Thresholds Form */}
      <Card>
        <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>
          Heuristic Detection Thresholds
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 18 }}>
          Fine-tune the sensitivity of rule evaluation engines for future PCAP ingestions.
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
          {DETECTION_FIELDS.map(({ key, label, desc, unit }) => (
            <div
              key={key}
              style={{
                padding: 14,
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
              }}
            >
              <label style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', display: 'block', marginBottom: 3 }}>
                {label}
              </label>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.4 }}>
                {desc}
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <input
                  type="number"
                  className="soc-input"
                  style={{ width: 110, fontFamily: 'JetBrains Mono' }}
                  value={(form[key] as number) || 0}
                  onChange={(e) => setForm({ ...form, [key]: parseInt(e.target.value) || 0 })}
                  min={0}
                />
                <span style={{ fontSize: 11.5, color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>{unit}</span>
              </div>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 22, display: 'flex', gap: 12, alignItems: 'center' }}>
          <button className="btn-primary" onClick={handleSave} style={{ padding: '8px 18px', fontSize: 13 }}>
            Save Platform Settings
          </button>
          {saved && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--success)', fontWeight: 600 }}>
              <CheckCircle2 size={14} /> Settings updated successfully!
            </div>
          )}
        </div>
      </Card>

      {/* Intellectual Property & Governance */}
      <Card>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
          <HardDrive size={16} color="var(--accent)" />
          <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
            Intellectual Property & Platform Governance
          </h3>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
          <div style={{ padding: 14, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: 'JetBrains Mono' }}>
              Platform Organization
            </div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>
              Nova Cyber Spark™
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              Enterprise Network Traffic Forensics & Cyber Intelligence
            </div>
          </div>

          <div style={{ padding: 14, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: 'JetBrains Mono' }}>
              Founder & Chief Architect
            </div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent)', marginTop: 4 }}>
              Pranay Kumar Mallem
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              Platform Author, Security Research & Architecture
            </div>
          </div>

          <div style={{ padding: 14, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: 'JetBrains Mono' }}>
              Patent & Intellectual Property
            </div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>
              Patent Rights Reserved
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              © 2026 Nova Cyber Spark · All Patents & Rights Assigned
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default SettingsPage;
