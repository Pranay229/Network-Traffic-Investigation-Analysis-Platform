import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity, Monitor, Globe, AlertTriangle, Wifi,
  Clock, Package, TrendingUp, Shield, Upload, FileText,
  ArrowRight, Radio, CheckCircle2, Radar, Layers
} from 'lucide-react';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis, CartesianGrid
} from 'recharts';
import { KPICard, SectionHeader, Card, LoadingSpinner, EmptyState } from '../components/UI';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { getOverview, getInvestigations, getAlerts, formatBytes, getScans, getIOCs } from '../services/api';
import type { OverviewData, Investigation, Alert, ScanRecord } from '../types';
import { formatLocalDateTime, formatRelativeTime } from '../utils/time';

const PROTO_COLORS: Record<string, string> = {
  TCP: '#3b82f6',
  UDP: '#8b5cf6',
  DNS: '#10b981',
  HTTP: '#f59e0b',
  ICMP: '#f97316',
  TLS: '#ef4444',
  ARP: '#06b6d4',
  OTHER: '#64748b',
};

export const Overview: React.FC = () => {
  const [data, setData] = useState<OverviewData | null>(null);
  const [recentInvs, setRecentInvs] = useState<Investigation[]>([]);
  const [scansList, setScansList] = useState<ScanRecord[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [iocCount, setIocCount] = useState<number>(0);
  const [timeRange, setTimeRange] = useState<'1H' | '6H' | '12H' | '24H' | 'ALL'>('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const invId = localStorage.getItem('selected_inv') || '';

  useEffect(() => {
    loadAllData();
    const id = setInterval(() => {
      if (data?.investigation?.status === 'processing' || data?.investigation?.status === 'pending') {
        loadAllData();
      }
    }, 4000);
    return () => clearInterval(id);
  }, [invId]);

  const loadAllData = async () => {
    try {
      const [invs, scans] = await Promise.all([
        getInvestigations().catch(() => []),
        getScans().catch(() => []),
      ]);
      setRecentInvs(invs);
      setScansList(scans);

      const targetId = invId || (invs.length > 0 ? invs[0].inv_id : null);
      if (targetId) {
        if (!invId && invs.length > 0) {
          localStorage.setItem('selected_inv', targetId);
        }
        const [overviewData, alertsData, iocData] = await Promise.all([
          getOverview(targetId),
          getAlerts(targetId).catch(() => []),
          getIOCs(targetId).catch(() => ({ total: 0, iocs: [] })),
        ]);
        setData(overviewData);
        setRecentAlerts(alertsData);
        setIocCount(iocData?.total || 0);
      }
      setError(null);
    } catch {
      setError('Unable to load investigation overview. Please ensure the API is reachable.');
    } finally {
      setLoading(false);
    }
  };

  if (!invId && recentInvs.length === 0 && !loading) {
    return (
      <div className="fade-in space-y-6">
        <SectionHeader
          title="Security Overview"
          subtitle="Monitor, investigate and analyze captured network traffic."
          icon={<Shield size={18} />}
          actions={
            <Link to="/upload" className="btn-primary">
              <Upload size={14} /> Upload PCAP
            </Link>
          }
        />

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 14 }}>
          {[
            { icon: <Upload size={22} />, title: 'Upload PCAP Capture', desc: 'Drag and drop .pcap or .pcapng files for deep packet inspection', to: '/upload', color: '#06b6d4' },
            { icon: <Activity size={22} />, title: 'Traffic Analysis', desc: 'Inspect flow rates, throughput volume, and protocols', to: '/traffic', color: '#10b981' },
            { icon: <AlertTriangle size={22} />, title: 'Threat Detections', desc: 'Automated heuristic anomaly rules and port scan detection', to: '/alerts', color: '#f97316' },
            { icon: <FileText size={22} />, title: 'Executive Reports', desc: 'Generate high-fidelity Markdown and printable investigation reports', to: '/reports', color: '#8b5cf6' },
          ].map((card) => (
            <Link key={card.to} to={card.to} style={{ textDecoration: 'none' }}>
              <div
                className="soc-card"
                style={{
                  padding: 22,
                  borderLeft: `3px solid ${card.color}`,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.transform = 'translateY(-2px)';
                  (e.currentTarget as HTMLElement).style.borderColor = card.color;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.transform = '';
                  (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)';
                }}
              >
                <div style={{ color: card.color, marginBottom: 12 }}>{card.icon}</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                  {card.title}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  {card.desc}
                </div>
              </div>
            </Link>
          ))}
        </div>

        <Card>
          <EmptyState
            icon={<Shield size={44} />}
            title="No Investigations Yet"
            message="Upload your first packet capture file (.pcap / .pcapng) to begin automated network traffic investigation and threat detection."
            action={
              <Link to="/upload" className="btn-primary" style={{ marginTop: 8 }}>
                <Upload size={14} /> Upload First PCAP
              </Link>
            }
          />
        </Card>
      </div>
    );
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 350 }}>
        <div style={{ textAlign: 'center' }}>
          <LoadingSpinner size={34} />
          <div style={{ marginTop: 12, color: 'var(--text-muted)', fontSize: 12.5, fontFamily: 'JetBrains Mono' }}>
            Loading SOC Investigation Telemetry...
          </div>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <Card>
        <EmptyState
          icon={<AlertTriangle size={40} />}
          title="Telemetry Load Error"
          message={error || 'No overview data available.'}
          action={
            <button className="btn-primary" onClick={loadAllData}>
              Try Again
            </button>
          }
        />
      </Card>
    );
  }

  const { kpi, protocol_distribution, traffic_timeline, investigation, packets_per_second } = data;

  // Processing state with pipeline stepper
  if (investigation.status === 'processing' || investigation.status === 'pending') {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Analysis in Progress"
          subtitle={`Pipeline analyzing ${investigation.filename} (${investigation.inv_id})`}
          icon={<Activity size={18} />}
        />
        <Card>
          <div style={{ textAlign: 'center', padding: '36px 16px' }}>
            <LoadingSpinner size={42} />
            <div style={{ marginTop: 16, fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
              {investigation.current_stage || 'Executing Deep Packet Inspection...'}
            </div>
            <div style={{ marginTop: 6, fontSize: 12.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
              {investigation.filename} · {investigation.inv_id}
            </div>

            <div style={{ maxWidth: 460, margin: '24px auto 0' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 12 }}>
                <span style={{ color: 'var(--text-secondary)' }}>Analysis Progress</span>
                <span style={{ color: 'var(--accent)', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                  {investigation.progress}%
                </span>
              </div>
              <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${investigation.progress}%`,
                    background: 'linear-gradient(90deg, #06b6d4, #3b82f6)',
                    transition: 'width 0.3s ease',
                  }}
                />
              </div>
            </div>
          </div>
        </Card>
      </div>
    );
  }

  // Format timeline data
  let timelineData = traffic_timeline.map((t, i, arr) => ({
    time: i === 0 ? '0s' : `${Math.round(t.timestamp - arr[0].timestamp)}s`,
    packets: t.packets,
  }));

  if (timeRange === '1H') timelineData = timelineData.slice(-15);
  else if (timeRange === '6H') timelineData = timelineData.slice(-30);
  else if (timeRange === '12H') timelineData = timelineData.slice(-45);
  else if (timeRange === '24H') timelineData = timelineData.slice(-60);

  const protoData = protocol_distribution.slice(0, 8).map((p) => ({
    name: p.protocol,
    value: p.count,
    color: PROTO_COLORS[p.protocol] || '#64748b',
  }));

  return (
    <div className="fade-in space-y-5">
      {/* Top Section Header */}
      <SectionHeader
        title="Security Overview"
        subtitle="Monitor, investigate and analyze captured network traffic."
        icon={<Shield size={18} />}
        actions={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <Link to="/upload" className="btn-primary">
              <Upload size={13} /> Upload PCAP
            </Link>
          </div>
        }
      />

      {/* KPI Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12 }}>
        <KPICard
          label="Total Packets"
          value={kpi.total_packets}
          icon={<Package size={18} />}
          color="#3b82f6"
          subtitle={`${packets_per_second ?? 0} pkts/sec`}
        />
        <KPICard
          label="Unique Hosts"
          value={kpi.unique_hosts}
          icon={<Monitor size={18} />}
          color="#10b981"
          subtitle="Network assets"
        />
        <KPICard
          label="DNS Queries"
          value={kpi.dns_queries}
          icon={<Globe size={18} />}
          color="#06b6d4"
          subtitle="Lookups"
        />
        <KPICard
          label="Potential Alerts"
          value={kpi.total_alerts}
          icon={<AlertTriangle size={18} />}
          color={kpi.total_alerts > 0 ? '#ef4444' : '#10b981'}
          subtitle={kpi.total_alerts > 0 ? 'Requires analyst review' : 'No anomalies'}
        />
        <KPICard
          label="TCP Connections"
          value={kpi.tcp_packets}
          icon={<Wifi size={18} />}
          color="#8b5cf6"
          subtitle="Transport streams"
        />
        <KPICard
          label="Total Bytes"
          value={formatBytes(kpi.total_bytes)}
          icon={<TrendingUp size={18} />}
          color="#f59e0b"
          subtitle="Traffic volume"
        />
        <KPICard
          label="ICMP Packets"
          value={kpi.icmp_packets}
          icon={<Radio size={18} />}
          color="#f97316"
          subtitle="Control messages"
        />
        <KPICard
          label="Capture Duration"
          value={`${investigation.capture_duration.toFixed(1)}s`}
          icon={<Clock size={18} />}
          color="#64748b"
          subtitle={new Date(investigation.created_at).toLocaleDateString()}
        />
      </div>

      {/* Network Activity Section */}
      <Card style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Activity size={17} color="var(--accent)" />
            <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
              Network Activity & Scan Operations Overview
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, fontFamily: 'JetBrains Mono', color: 'var(--text-muted)' }}>
            <Clock size={13} />
            <span>Latest Activity: </span>
            <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
              {scansList[0]?.scan_completed_at
                ? formatLocalDateTime(scansList[0].scan_completed_at)
                : investigation?.created_at
                ? formatLocalDateTime(investigation.created_at)
                : 'Active'}
            </span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12 }}>
          <KPICard
            label="Total Hosts"
            value={(kpi.unique_hosts || 0) + scansList.reduce((acc, s) => acc + (s.hosts_count || 0), 0)}
            icon={<Monitor size={16} />}
            color="#10b981"
            subtitle="Network assets"
          />
          <KPICard
            label="Open Ports"
            value={scansList.reduce((acc, s) => acc + (s.ports_count || 0), 0)}
            icon={<Layers size={16} />}
            color="#ec4899"
            subtitle="Discovered sockets"
          />
          <KPICard
            label="Total Packets"
            value={kpi.total_packets.toLocaleString()}
            icon={<Package size={16} />}
            color="#3b82f6"
            subtitle={`${packets_per_second ?? 0} pkts/sec`}
          />
          <KPICard
            label="Total Bytes"
            value={formatBytes(kpi.total_bytes)}
            icon={<TrendingUp size={16} />}
            color="#f59e0b"
            subtitle="Network volume"
          />
          <KPICard
            label="Active Investigations"
            value={recentInvs.length}
            icon={<Shield size={16} />}
            color="#06b6d4"
            subtitle="Triage cases"
          />
          <KPICard
            label="Security Events"
            value={(kpi.total_alerts || 0) + scansList.reduce((acc, s) => acc + (s.findings_count || 0), 0)}
            icon={<AlertTriangle size={16} />}
            color={((kpi.total_alerts || 0) + scansList.reduce((acc, s) => acc + (s.findings_count || 0), 0)) > 0 ? '#f97316' : '#10b981'}
            subtitle="Correlated signals"
          />
          <KPICard
            label="High/Critical Events"
            value={recentAlerts.filter(a => a.severity === 'high' || a.severity === 'critical').length}
            icon={<AlertTriangle size={16} />}
            color={recentAlerts.filter(a => a.severity === 'high' || a.severity === 'critical').length > 0 ? '#ef4444' : '#10b981'}
            subtitle="Elevated priority"
          />
          <KPICard
            label="IOCs Extracted"
            value={iocCount}
            icon={<Radar size={16} />}
            color="#8b5cf6"
            subtitle="Observable indicators"
          />
          <KPICard
            label="High Traffic Events"
            value={recentAlerts.filter(a => (a.title || a.category || '').toLowerCase().includes('traffic') || (a.rule_id || '').includes('NET-002') || (a.rule_id || '').includes('NET-003')).length}
            icon={<TrendingUp size={16} />}
            color="#eab308"
            subtitle="Exceeded thresholds"
          />
          <KPICard
            label="Potential Anomalies"
            value={recentAlerts.length}
            icon={<Activity size={16} />}
            color={recentAlerts.length > 0 ? '#ef4444' : '#10b981'}
            subtitle="Baseline deviations"
          />
        </div>
      </Card>

      {/* Main Dashboard Grid: Traffic Activity & Protocol Distribution */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
        {/* Traffic Activity Chart */}
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div>
              <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)' }}>
                Traffic Activity
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Packet throughput distribution over capture timeline</div>
            </div>
            {/* Time Controls */}
            <div style={{ display: 'flex', gap: 3, background: 'var(--bg-secondary)', padding: 3, borderRadius: 6, border: '1px solid var(--border)' }}>
              {(['1H', '6H', '12H', '24H', 'ALL'] as const).map((r) => (
                <button
                  key={r}
                  onClick={() => setTimeRange(r)}
                  style={{
                    padding: '2px 8px',
                    fontSize: 10.5,
                    fontWeight: 700,
                    fontFamily: 'JetBrains Mono',
                    borderRadius: 4,
                    border: 'none',
                    cursor: 'pointer',
                    background: timeRange === r ? 'var(--accent)' : 'transparent',
                    color: timeRange === r ? '#ffffff' : 'var(--text-muted)',
                    transition: 'all 0.15s',
                  }}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>

          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="trafficGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="time" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} stroke="var(--border)" />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} stroke="var(--border)" />
              <Tooltip
                contentStyle={{
                  background: '#0f172a',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  fontSize: 11.5,
                  fontFamily: 'JetBrains Mono',
                }}
                formatter={(val: any) => [typeof val === 'number' ? val.toLocaleString() : String(val), 'Packets']}
              />
              <Area type="monotone" dataKey="packets" stroke="#06b6d4" strokeWidth={2} fill="url(#trafficGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        {/* Protocol Distribution Donut Chart */}
        <Card>
          <div style={{ fontSize: 13.5, fontWeight: 700, marginBottom: 4, color: 'var(--text-primary)' }}>
            Protocol Distribution
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>Breakdown by layer type</div>

          <ResponsiveContainer width="100%" height={175}>
            <PieChart>
              <Pie
                data={protoData}
                cx="50%"
                cy="50%"
                innerRadius={46}
                outerRadius={72}
                paddingAngle={3}
                dataKey="value"
              >
                {protoData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: '#0f172a',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  fontSize: 11.5,
                  fontFamily: 'JetBrains Mono',
                }}
                formatter={(val: any) => [typeof val === 'number' ? val.toLocaleString() : String(val), 'Packets']}
              />
            </PieChart>
          </ResponsiveContainer>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginTop: 4 }}>
            {protoData.map((p) => (
              <div key={p.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
                <div style={{ width: 7, height: 7, borderRadius: 2, background: p.color }} />
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono' }}>{p.name}</span>
                <span style={{ color: 'var(--text-muted)', marginLeft: 'auto', fontFamily: 'JetBrains Mono', fontSize: 10 }}>
                  {p.value.toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Potentially Suspicious Activity & Capture Intel Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Potentially Suspicious Activity Feed */}
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div>
              <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)' }}>
                Potentially Suspicious Activity
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Heuristic detection anomalies flagged by analysis engine</div>
            </div>
            <Link to="/alerts" className="btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }}>
              View All <ArrowRight size={11} />
            </Link>
          </div>

          {recentAlerts.length === 0 ? (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
              <CheckCircle2 size={28} style={{ margin: '0 auto 8px', color: 'var(--success)' }} />
              No security anomalies detected in this capture.
            </div>
          ) : (
            <div className="space-y-2">
              {recentAlerts.map((a) => (
                <div
                  key={a.alert_id}
                  style={{
                    padding: '10px 12px',
                    borderRadius: 6,
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 8,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                    <SeverityBadge severity={a.severity} size="sm" />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {a.alert_type}
                      </div>
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                        {a.src_ip || '—'} → {a.dst_ip || '—'}
                      </div>
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                      {a.first_seen_str ? a.first_seen_str.slice(11, 19) : '—'}
                    </div>
                    <StatusBadge status={a.status} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Capture Intelligence Summary */}
        <Card>
          <div style={{ fontSize: 13.5, fontWeight: 700, marginBottom: 4, color: 'var(--text-primary)' }}>
            Investigation Metadata
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>Telemetry parameters for {investigation.inv_id}</div>

          {[
            { label: 'File Name', value: investigation.filename },
            { label: 'Investigation ID', value: investigation.inv_id, mono: true, accent: true },
            { label: 'File Hash (SHA-256)', value: investigation.file_hash ? investigation.file_hash.slice(0, 24) + '...' : '—', mono: true },
            { label: 'Capture Status', value: <StatusBadge status={investigation.status} /> },
            { label: 'Total Volume', value: `${formatBytes(investigation.total_bytes)} (${investigation.total_packets.toLocaleString()} packets)` },
            { label: 'Duration Window', value: `${investigation.capture_duration.toFixed(2)}s` },
            { label: 'Total Hosts Discovered', value: investigation.unique_hosts },
            { label: 'Created At', value: new Date(investigation.created_at).toLocaleString() },
          ].map(({ label, value, mono, accent }) => (
            <div
              key={label}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '7px 0',
                borderBottom: '1px solid var(--border-subtle)',
                fontSize: 12,
              }}
            >
              <span style={{ color: 'var(--text-muted)' }}>{label}</span>
              <span
                style={{
                  color: accent ? 'var(--accent)' : 'var(--text-primary)',
                  fontFamily: mono ? 'JetBrains Mono' : undefined,
                  fontWeight: mono || accent ? 600 : 400,
                  maxWidth: 240,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {value}
              </span>
            </div>
          ))}
        </Card>
      </div>

      {/* Active Investigations Table */}
      <Card style={{ padding: 0 }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)' }}>
              Recent PCAP Investigations
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Analyzed network captures available in this session</div>
          </div>
          <Link to="/investigations" className="btn-ghost" style={{ fontSize: 11.5 }}>
            Manage All <ArrowRight size={12} />
          </Link>
        </div>

        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 140 }}>Investigation ID</th>
              <th>PCAP File</th>
              <th style={{ width: 120 }}>Packets</th>
              <th style={{ width: 120 }}>Traffic</th>
              <th style={{ width: 90 }}>Alerts</th>
              <th style={{ width: 120 }}>Status</th>
              <th style={{ width: 90 }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {recentInvs.slice(0, 5).map((inv) => (
              <tr
                key={inv.inv_id}
                style={{ cursor: 'pointer', background: inv.inv_id === invId ? 'rgba(6,182,212,0.06)' : undefined }}
                onClick={() => {
                  localStorage.setItem('selected_inv', inv.inv_id);
                  loadAllData();
                }}
              >
                <td>
                  <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>
                    {inv.inv_id}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500 }}>
                    {inv.filename}
                  </span>
                </td>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                  {inv.total_packets.toLocaleString()}
                </td>
                <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                  {formatBytes(inv.total_bytes)}
                </td>
                <td>
                  <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, fontWeight: 700, color: inv.total_alerts > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
                    {inv.total_alerts}
                  </span>
                </td>
                <td>
                  <StatusBadge status={inv.status} />
                </td>
                <td>
                  <button
                    className="btn-ghost"
                    style={{ fontSize: 11, padding: '3px 8px' }}
                    onClick={(e) => {
                      e.stopPropagation();
                      localStorage.setItem('selected_inv', inv.inv_id);
                      loadAllData();
                    }}
                  >
                    Select
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
};

export default Overview;
