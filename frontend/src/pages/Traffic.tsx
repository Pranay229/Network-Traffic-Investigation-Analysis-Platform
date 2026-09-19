import React, { useState, useEffect } from 'react';
import { Wifi, RefreshCw, Activity, Layers, TrendingUp, AlertTriangle, ArrowRight } from 'lucide-react';
import {
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, Cell, PieChart, Pie,
} from 'recharts';
import { SectionHeader, Card, KPICard, EmptyState, LoadingSpinner, Drawer } from '../components/UI';
import { ProtoChip } from '../components/Badges';
import { getProtocols, getTrafficActivity } from '../services/api';
import type { TrafficActivityResponse, TrafficFlow } from '../types';
import {
  formatLocalDateTime, formatDuration, formatByteSize, formatRate
} from '../utils/time';

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

export const TrafficAnalysis: React.FC = () => {
  const [data, setData] = useState<any>(null);
  const [trafficActivity, setTrafficActivity] = useState<TrafficActivityResponse | null>(null);
  const [selectedFlow, setSelectedFlow] = useState<TrafficFlow | null>(null);
  const [loading, setLoading] = useState(true);
  const invId = localStorage.getItem('selected_inv') || '';

  const loadData = async () => {
    if (!invId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const [resProtocols, resActivity] = await Promise.all([
        getProtocols(invId).catch(() => null),
        getTrafficActivity(invId).catch(() => null),
      ]);
      setData(resProtocols);
      setTrafficActivity(resActivity);
    } catch {
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId]);

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Traffic Analysis"
          subtitle="Transport, Network, and Application layer protocol distribution"
          icon={<Wifi size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Wifi size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to inspect protocol distributions and bandwidth timelines."
          />
        </Card>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Traffic Analysis"
          subtitle="Transport, Network, and Application layer protocol distribution"
          icon={<Wifi size={18} />}
        />
        <Card>
          <div style={{ display: 'flex', justifyContent: 'center', padding: '64px 0' }}>
            <LoadingSpinner size={32} />
          </div>
        </Card>
      </div>
    );
  }

  const protoData = Object.entries(data?.protocol_counts || {})
    .map(([k, v]) => ({
      protocol: k,
      count: Number(v),
      color: PROTO_COLORS[k] || '#64748b',
    }))
    .sort((a, b) => b.count - a.count);

  const timeline = (data?.timeline || []).slice(-80).map((t: any, i: number, arr: any[]) => ({
    time: i === 0 ? '0s' : `${Math.round(t.timestamp - arr[0].timestamp)}s`,
    packets: t.packets,
  }));

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="Traffic Analysis"
        subtitle={`${(data?.total_packets || 0).toLocaleString()} packets across ${protoData.length} distinct protocol layers`}
        icon={<Wifi size={18} />}
        actions={
          <button className="btn-ghost" onClick={loadData} style={{ fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        }
      />

      {/* KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12 }}>
        <KPICard
          label="Total Packets"
          value={data?.total_packets || 0}
          icon={<Layers size={18} />}
          color="#06b6d4"
          subtitle="Analyzed frames"
        />
        <KPICard
          label="Packets Per Second"
          value={(data?.packets_per_second || 0).toFixed(1)}
          icon={<Activity size={18} />}
          color="#3b82f6"
          subtitle="Throughput rate"
        />
        <KPICard
          label="Capture Duration"
          value={`${(data?.capture_duration || 0).toFixed(1)}s`}
          icon={<TrendingUp size={18} />}
          color="#10b981"
          subtitle="Total capture time"
        />
        <KPICard
          label="Active Protocols"
          value={protoData.length}
          icon={<Wifi size={18} />}
          color="#8b5cf6"
          subtitle="Identified standards"
        />
      </div>

      {/* Charts Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
        {/* Timeline Area Chart */}
        <Card>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Traffic Throughput Timeline
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
            Frame rate distribution over time
          </div>

          <ResponsiveContainer width="100%" height={230}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="trafficTimelineGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
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
                formatter={(val: any) => [val, 'Packets']}
              />
              <Area type="monotone" dataKey="packets" stroke="#3b82f6" strokeWidth={2} fill="url(#trafficTimelineGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        {/* Donut Chart */}
        <Card>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Layer Breakdown
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
            Protocol packet shares
          </div>

          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={protoData} dataKey="count" nameKey="protocol" cx="50%" cy="50%" innerRadius={46} outerRadius={72} paddingAngle={3}>
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
                formatter={(val: any) => [val, 'Packets']}
              />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Traffic Activity & High Traffic Detection Section */}
      {trafficActivity && (
        <Card style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Activity size={16} color="var(--accent)" />
                <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                  Real Traffic Activity Analysis & Flow Dynamics
                </span>
                {(trafficActivity.summary?.high_traffic_flows_count ?? 0) > 0 && (
                  <span style={{
                    fontSize: 10.5,
                    fontWeight: 700,
                    padding: '2px 7px',
                    borderRadius: 4,
                    background: 'rgba(239, 68, 68, 0.15)',
                    color: 'var(--danger)',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4
                  }}>
                    <AlertTriangle size={11} />
                    {trafficActivity.summary.high_traffic_flows_count} High Traffic Flows
                  </span>
                )}
              </div>
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 2 }}>
                Calculated directly from analyzed packet timestamps, payload byte lengths, and bidirectional flow intervals
              </div>
            </div>

            {/* Threshold info badge */}
            <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--text-dim)', background: 'var(--bg-secondary)', padding: '4px 10px', borderRadius: 6, border: '1px solid var(--border)' }}>
              Thresholds: PPS &gt; {trafficActivity.thresholds?.high_packet_rate} · Rate &gt; {formatRate(trafficActivity.thresholds?.high_byte_rate)}
            </div>
          </div>

          {/* High Traffic Advisory Banner if triggered */}
          {(trafficActivity.summary?.high_traffic_flows_count ?? 0) > 0 && (
            <div style={{
              margin: '12px 18px 0',
              padding: '10px 14px',
              borderRadius: 6,
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              display: 'flex',
              alignItems: 'flex-start',
              gap: 10,
            }}>
              <AlertTriangle size={16} color="var(--warning)" style={{ flexShrink: 0, marginTop: 2 }} />
              <div style={{ fontSize: 12, lineHeight: 1.5, color: 'var(--text-secondary)' }}>
                <strong style={{ color: 'var(--text-primary)' }}>Potentially unusual traffic volume detected: </strong>
                This may represent legitimate data transfer (such as system updates, backups, large downloads) or abnormal network activity. Additional investigation is required to determine whether the activity is legitimate or suspicious.
              </div>
            </div>
          )}

          {/* Flows Table */}
          <div style={{ overflowX: 'auto', padding: '12px 18px' }}>
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Endpoints (Source → Destination)</th>
                  <th>Protocol</th>
                  <th>First Observed</th>
                  <th>Last Observed</th>
                  <th>Duration</th>
                  <th style={{ textAlign: 'right' }}>Packets</th>
                  <th style={{ textAlign: 'right' }}>Total Volume</th>
                  <th style={{ textAlign: 'right' }}>Average Rate</th>
                  <th>Classification</th>
                  <th style={{ textAlign: 'right' }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {(!trafficActivity.flows || trafficActivity.flows.length === 0) ? (
                  <tr>
                    <td colSpan={10} style={{ textAlign: 'center', padding: 28, color: 'var(--text-muted)' }}>
                      No conversational flows recorded in this PCAP.
                    </td>
                  </tr>
                ) : (
                  trafficActivity.flows.map((fl, i) => (
                    <tr
                      key={fl.flow_id || i}
                      style={{
                        background: fl.is_high_traffic ? 'rgba(245, 158, 11, 0.04)' : undefined,
                        cursor: 'pointer',
                      }}
                      onClick={() => setSelectedFlow(fl)}
                    >
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'JetBrains Mono', fontSize: 11.5 }}>
                          <span style={{ color: 'var(--accent)', fontWeight: 600 }}>
                            {fl.src_ip}:{fl.src_port || '—'}
                          </span>
                          <ArrowRight size={11} color="var(--text-dim)" />
                          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                            {fl.dst_ip}:{fl.dst_port || '—'}
                          </span>
                        </div>
                      </td>
                      <td>
                        <ProtoChip protocol={fl.protocol} />
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                        {formatLocalDateTime(fl.first_observed)}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                        {formatLocalDateTime(fl.last_observed)}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-secondary)' }}>
                        {formatDuration(fl.duration_seconds)}
                      </td>
                      <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                        {fl.packet_count.toLocaleString()}
                      </td>
                      <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {formatByteSize(fl.total_bytes)}
                      </td>
                      <td style={{ textAlign: 'right', fontFamily: 'JetBrains Mono', color: fl.is_high_traffic ? 'var(--warning)' : 'var(--text-muted)' }}>
                        {formatRate(fl.bytes_per_second)} ({fl.packets_per_second.toFixed(1)} pps)
                      </td>
                      <td>
                        {fl.is_high_traffic ? (
                          <span style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 3,
                            padding: '2px 7px',
                            borderRadius: 4,
                            fontSize: 10.5,
                            fontWeight: 700,
                            background: 'rgba(245, 158, 11, 0.15)',
                            color: 'var(--warning)',
                          }}>
                            HIGH TRAFFIC
                          </span>
                        ) : (
                          <span style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 3,
                            padding: '2px 7px',
                            borderRadius: 4,
                            fontSize: 10.5,
                            fontWeight: 600,
                            color: 'var(--text-dim)',
                          }}>
                            NORMAL
                          </span>
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn-ghost"
                          style={{ padding: '3px 8px', fontSize: 11 }}
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedFlow(fl);
                          }}
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Protocol Breakdown Table */}
      <Card style={{ padding: 0 }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)' }}>
            Protocol Breakdown Table
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Packet counts and bandwidth percentage per protocol</div>
        </div>

        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 180 }}>Protocol</th>
              <th style={{ width: 140 }}>Packet Count</th>
              <th style={{ width: 120 }}>% of Total Traffic</th>
              <th>Proportional Share</th>
            </tr>
          </thead>
          <tbody>
            {protoData.map((p) => {
              const pct = data?.total_packets ? ((p.count / data.total_packets) * 100).toFixed(1) : '0';
              return (
                <tr key={p.protocol}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 8, height: 8, borderRadius: 2, background: p.color, flexShrink: 0 }} />
                      <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12.5, fontWeight: 700, color: p.color }}>
                        {p.protocol}
                      </span>
                    </div>
                  </td>
                  <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12.5, fontWeight: 600 }}>
                    {p.count.toLocaleString()}
                  </td>
                  <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--text-muted)' }}>
                    {pct}%
                  </td>
                  <td style={{ width: 260 }}>
                    <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ height: '100%', background: p.color, borderRadius: 3, width: `${pct}%` }} />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>

      {/* Flow Details Drawer */}
      <Drawer
        isOpen={!!selectedFlow}
        onClose={() => setSelectedFlow(null)}
        title={selectedFlow ? `${selectedFlow.is_high_traffic ? 'High Traffic Flow' : 'Conversation Flow'} Details` : 'Flow Details'}
        subtitle={selectedFlow ? `${selectedFlow.src_ip} → ${selectedFlow.dst_ip}` : ''}
        width={560}
      >
        {selectedFlow && (
          <div className="space-y-4" style={{ padding: '8px 0' }}>
            {/* Header info */}
            <div style={{ padding: 14, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div style={{ fontSize: 16, fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono' }}>
                  {selectedFlow.protocol} Flow
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  {selectedFlow.is_high_traffic && (
                    <span style={{ padding: '2px 8px', borderRadius: 4, background: 'rgba(245, 158, 11, 0.15)', color: 'var(--warning)', fontWeight: 700, fontSize: 11 }}>
                      HIGH TRAFFIC
                    </span>
                  )}
                  <ProtoChip protocol={selectedFlow.protocol} />
                </div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                {selectedFlow.is_high_traffic
                  ? 'Traffic volume or transmission rate exceeded the configured thresholds for this conversation.'
                  : 'Normal bidirectional conversation telemetry within configured thresholds.'}
              </div>
            </div>

            {/* Metrics Breakdown Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 12 }}>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>First Observed</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', marginTop: 2 }}>
                  {formatLocalDateTime(selectedFlow.first_observed)}
                </div>
              </div>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Last Observed</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', marginTop: 2 }}>
                  {formatLocalDateTime(selectedFlow.last_observed)}
                </div>
              </div>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Flow Duration</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600, marginTop: 2 }}>
                  {formatDuration(selectedFlow.duration_seconds)}
                </div>
              </div>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Total Packets</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600, marginTop: 2 }}>
                  {selectedFlow.packet_count.toLocaleString()}
                </div>
              </div>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Total Data Volume</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600, marginTop: 2 }}>
                  {formatByteSize(selectedFlow.total_bytes)}
                </div>
              </div>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Average Transfer Rate</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: selectedFlow.is_high_traffic ? 'var(--warning)' : 'var(--text-primary)', fontWeight: 600, marginTop: 2 }}>
                  {formatRate(selectedFlow.bytes_per_second)} ({selectedFlow.packets_per_second.toFixed(1)} pps)
                </div>
              </div>
            </div>

            {/* Evidence, Analysis, Recommendations */}
            <div className="space-y-3">
              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  OBSERVATION
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedFlow.is_high_traffic
                    ? `Traffic volume exceeded configured threshold: ${selectedFlow.packet_count.toLocaleString()} packets (${formatByteSize(selectedFlow.total_bytes)}) transferred at ${formatRate(selectedFlow.bytes_per_second)}.`
                    : `Normal flow observed between ${selectedFlow.src_ip}:${selectedFlow.src_port || '—'} and ${selectedFlow.dst_ip}:${selectedFlow.dst_port || '—'}.`}
                </div>
              </div>

              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--warning)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  ANALYSIS
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Unusually high traffic can be caused by legitimate transfers, backups, streaming, updates, or abnormal network activity. Additional context is required before determining whether it represents a security incident.
                </div>
              </div>

              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--success)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  RECOMMENDATION
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  Verify whether the data transfer was expected during this timeframe and whether the endpoints correspond to authorized servers or internal infrastructure.
                </div>
              </div>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};

export default TrafficAnalysis;
