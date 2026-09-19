import React, { useState, useEffect } from 'react';
import {
  Clock, RefreshCw, Radio, Globe, Server, Terminal, AlertTriangle,
  Filter, Search, ShieldAlert, Activity, ArrowRight, ExternalLink, Info
} from 'lucide-react';
import { SectionHeader, Card, EmptyState, LoadingSpinner, Drawer } from '../components/UI';
import { SeverityBadge, ProtoChip } from '../components/Badges';
import { getTimeline } from '../services/api';
import type { TimelineEvent } from '../types';
import {
  formatLocalDateTime, formatPreciseTimestamp, formatRelativeTime, formatDuration, formatByteSize
} from '../utils/time';

export const Timeline: React.FC = () => {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  
  // Filtering
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);

  const invId = localStorage.getItem('selected_inv') || '';

  const loadData = async () => {
    if (!invId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await getTimeline(invId, {
        severity: severityFilter !== 'all' ? severityFilter : undefined,
        category: categoryFilter !== 'all' ? categoryFilter : undefined,
        limit: 400,
      });
      setEvents(res.events || []);
      setTotal(res.total || (res.events ? res.events.length : 0));
    } catch {
      setEvents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [invId, severityFilter, categoryFilter]);

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Security Investigation Timeline"
          subtitle="Chronological sequence of captured packets, security events, and high traffic flows"
          icon={<Clock size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Clock size={40} />}
            title="No Investigation Selected"
            message="Select an active PCAP investigation from the top navigation to inspect the temporal event sequence."
          />
        </Card>
      </div>
    );
  }

  // Client-side text search filter
  const filteredEvents = events.filter((e) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchText = (
        (e.description || '') +
        ' ' +
        (e.event_type || e.type || '') +
        ' ' +
        (e.src_ip || e.source_ip || '') +
        ' ' +
        (e.dst_ip || e.destination_ip || '') +
        ' ' +
        (e.protocol || '')
      ).toLowerCase();
      if (!matchText.includes(q)) return false;
    }
    return true;
  });

  const getEventIcon = (e: TimelineEvent) => {
    const sev = (e.severity || 'info').toLowerCase();
    if (sev === 'critical' || sev === 'high' || e.type === 'alert') {
      return <AlertTriangle size={15} color="var(--danger)" />;
    }
    if (e.event_type === 'HIGH_TRAFFIC' || e.type === 'high_traffic') {
      return <Activity size={15} color="var(--warning)" />;
    }
    if (e.protocol === 'DNS') return <Globe size={15} color="#34d399" />;
    if (e.protocol === 'HTTP') return <Server size={15} color="#fbbf24" />;
    if (e.protocol === 'ICMP') return <Radio size={15} color="#fb923c" />;
    return <Terminal size={15} color="#60a5fa" />;
  };

  const getEventTypeName = (e: TimelineEvent) => {
    return (e.event_type || e.type || 'EVENT').toUpperCase();
  };

  return (
    <div className="fade-in space-y-4 max-w-7xl mx-auto">
      <SectionHeader
        title="Security Investigation Timeline"
        subtitle={`Chronological forensic event trace · ${total.toLocaleString()} real captured events recorded`}
        icon={<Clock size={18} />}
        actions={
          <button className="btn-ghost" onClick={loadData} style={{ fontSize: 12 }}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        }
      />

      {/* Filter Controls Card */}
      <Card style={{ padding: '14px 16px' }}>
        <div className="space-y-3">
          {/* Row 1: Severity Filters */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'JetBrains Mono', minWidth: 70 }}>
              Severity:
            </span>
            {[
              { id: 'all', label: 'All Severities' },
              { id: 'critical', label: 'Critical' },
              { id: 'high', label: 'High' },
              { id: 'medium', label: 'Medium' },
              { id: 'low', label: 'Low' },
              { id: 'info', label: 'Info' },
            ].map((s) => (
              <button
                key={s.id}
                onClick={() => setSeverityFilter(s.id)}
                className={severityFilter === s.id ? 'btn-primary' : 'btn-ghost'}
                style={{ fontSize: 11, padding: '4px 10px' }}
              >
                {s.label}
              </button>
            ))}
          </div>

          {/* Row 2: Category Filters & Search */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'JetBrains Mono', minWidth: 70 }}>
                Category:
              </span>
              {[
                { id: 'all', label: 'All' },
                { id: 'network', label: 'Network' },
                { id: 'dns', label: 'DNS' },
                { id: 'http', label: 'HTTP' },
                { id: 'tcp', label: 'TCP' },
                { id: 'icmp', label: 'ICMP' },
                { id: 'findings', label: 'Security Findings' },
                { id: 'high_traffic', label: 'High Traffic' },
                { id: 'iocs', label: 'IOCs' },
              ].map((c) => (
                <button
                  key={c.id}
                  onClick={() => setCategoryFilter(c.id)}
                  className={categoryFilter === c.id ? 'btn-primary' : 'btn-ghost'}
                  style={{ fontSize: 11, padding: '4px 10px' }}
                >
                  {c.label}
                </button>
              ))}
            </div>

            <div style={{ position: 'relative', width: 240 }}>
              <Search size={14} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="soc-input"
                style={{ paddingLeft: 28, fontSize: 11.5 }}
                placeholder="Search IP, protocol, description..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </div>
        </div>
      </Card>

      {/* Chronological Event Stream */}
      <Card style={{ padding: '20px 24px' }}>
        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 56 }}>
            <LoadingSpinner size={32} />
            <div style={{ marginTop: 12, fontSize: 12.5, color: 'var(--text-muted)' }}>
              Loading chronological investigation events...
            </div>
          </div>
        ) : filteredEvents.length === 0 ? (
          <EmptyState
            icon={<Clock size={40} />}
            title="No Events Found"
            message="No timeline events match your active severity and category filters."
          />
        ) : (
          <div style={{ position: 'relative', paddingLeft: 26 }}>
            {/* Continuous Vertical Timeline Track */}
            <div
              style={{
                position: 'absolute',
                top: 8,
                bottom: 8,
                left: 10,
                width: 2,
                background: 'var(--border)',
              }}
            />

            <div className="space-y-3">
              {filteredEvents.map((evt, idx) => {
                const sev = (evt.severity || 'info').toLowerCase();
                const isHighRisk = sev === 'high' || sev === 'critical' || evt.type === 'alert';
                const src = evt.src_ip || evt.source_ip;
                const dst = evt.dst_ip || evt.destination_ip;
                const srcP = evt.src_port || evt.source_port;
                const dstP = evt.dst_port || evt.destination_port;

                return (
                  <div
                    key={evt.event_id || idx}
                    onClick={() => setSelectedEvent(evt)}
                    style={{
                      position: 'relative',
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 14,
                      padding: '12px 16px',
                      borderRadius: 8,
                      background: isHighRisk ? 'rgba(239, 68, 68, 0.06)' : 'var(--bg-secondary)',
                      border: `1px solid ${isHighRisk ? 'rgba(239, 68, 68, 0.25)' : 'var(--border-subtle)'}`,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.borderColor = isHighRisk
                        ? 'rgba(239, 68, 68, 0.6)'
                        : 'var(--accent)';
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.borderColor = isHighRisk
                        ? 'rgba(239, 68, 68, 0.25)'
                        : 'var(--border-subtle)';
                    }}
                  >
                    {/* Event Node Dot */}
                    <div
                      style={{
                        position: 'absolute',
                        left: -22,
                        top: 16,
                        width: 14,
                        height: 14,
                        borderRadius: '50%',
                        background: isHighRisk ? 'var(--danger)' : sev === 'medium' ? 'var(--warning)' : 'var(--accent)',
                        border: '2px solid var(--bg-card)',
                      }}
                    />

                    <div style={{ minWidth: 26, marginTop: 2 }}>{getEventIcon(evt)}</div>

                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span
                            style={{
                              fontSize: 10.5,
                              fontFamily: 'JetBrains Mono',
                              fontWeight: 700,
                              padding: '2px 7px',
                              borderRadius: 4,
                              background: 'rgba(255,255,255,0.06)',
                              color: 'var(--text-primary)',
                            }}
                          >
                            {getEventTypeName(evt)}
                          </span>
                          <SeverityBadge severity={sev as any} size="sm" />
                          {evt.protocol && <ProtoChip protocol={evt.protocol} />}
                        </div>

                        {/* Timestamp with relative time badge */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600 }}>
                            {formatLocalDateTime(evt.timestamp_str || evt.timestamp)}
                          </span>
                          <span style={{ fontSize: 10.5, color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                            ({formatRelativeTime(evt.timestamp)})
                          </span>
                        </div>
                      </div>

                      <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', lineHeight: 1.45 }}>
                        {evt.description}
                      </div>

                      {/* Endpoint connection string if applicable */}
                      {(src || dst) && (
                        <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--text-dim)', marginTop: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ color: 'var(--accent)' }}>{src || '—'}{srcP ? `:${srcP}` : ''}</span>
                          <ArrowRight size={11} />
                          <span style={{ color: 'var(--text-secondary)' }}>{dst || '—'}{dstP ? `:${dstP}` : ''}</span>
                        </div>
                      )}

                      {/* Evidence Pill */}
                      {evt.evidence && (
                        <div style={{ marginTop: 6, fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--accent)', background: 'rgba(6, 182, 212, 0.06)', padding: '3px 8px', borderRadius: 4 }}>
                          Evidence: {evt.evidence}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </Card>

      {/* Rich Security Investigation Event Details Drawer */}
      <Drawer
        isOpen={!!selectedEvent}
        onClose={() => setSelectedEvent(null)}
        title={selectedEvent ? `${getEventTypeName(selectedEvent)} Event Details` : 'Event Details'}
        subtitle={selectedEvent ? formatLocalDateTime(selectedEvent.timestamp_str || selectedEvent.timestamp) : ''}
        width={560}
      >
        {selectedEvent && (
          <div className="space-y-4" style={{ padding: '8px 0' }}>
            {/* Header Badge Card */}
            <div style={{ padding: 14, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono' }}>
                  {getEventTypeName(selectedEvent)}
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <SeverityBadge severity={(selectedEvent.severity || 'info').toLowerCase() as any} />
                  {selectedEvent.protocol && <ProtoChip protocol={selectedEvent.protocol} />}
                </div>
              </div>
              <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {selectedEvent.description}
              </div>
            </div>

            {/* Endpoints & Metrics Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 12 }}>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Source Address</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--accent)', fontWeight: 600, marginTop: 2 }}>
                  {selectedEvent.src_ip || selectedEvent.source_ip || '—'}
                  {(selectedEvent.src_port || selectedEvent.source_port) ? `:${selectedEvent.src_port || selectedEvent.source_port}` : ''}
                </div>
              </div>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Destination Address</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600, marginTop: 2 }}>
                  {selectedEvent.dst_ip || selectedEvent.destination_ip || '—'}
                  {(selectedEvent.dst_port || selectedEvent.destination_port) ? `:${selectedEvent.dst_port || selectedEvent.destination_port}` : ''}
                </div>
              </div>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Exact Timestamp</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-secondary)', marginTop: 2 }}>
                  {formatPreciseTimestamp(selectedEvent.timestamp)}
                </div>
              </div>
              <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Flow Duration</div>
                <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-secondary)', marginTop: 2 }}>
                  {selectedEvent.duration_seconds != null ? formatDuration(selectedEvent.duration_seconds) : '—'}
                </div>
              </div>
              {selectedEvent.packet_count != null && (
                <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Packet Count</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600, marginTop: 2 }}>
                    {selectedEvent.packet_count.toLocaleString()} packets
                  </div>
                </div>
              )}
              {selectedEvent.bytes != null && (
                <div style={{ padding: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase' }}>Total Data Volume</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600, marginTop: 2 }}>
                    {formatByteSize(selectedEvent.bytes)}
                  </div>
                </div>
              )}
            </div>

            {/* Structured Evidence, Analysis & Recommendations */}
            <div className="space-y-3">
              {/* Evidence */}
              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  OBSERVATION / EVIDENCE
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedEvent.evidence || selectedEvent.description || 'Observed directly in captured packet analysis.'}
                </div>
              </div>

              {/* Analysis */}
              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--warning)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  ANALYSIS & WHY IT MATTERS
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedEvent.why_it_matters ||
                    (selectedEvent.event_type === 'HIGH_TRAFFIC'
                      ? 'Unusually high traffic can be caused by legitimate transfers, backups, streaming, updates, or abnormal network activity. Additional context is required before determining whether it represents a security incident.'
                      : 'Observed network event provides operational telemetry for host communications, potential exposure points, or abnormal protocol behavior.')}
                </div>
              </div>

              {/* Recommended Steps */}
              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--success)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  RECOMMENDED INVESTIGATION STEP
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedEvent.recommended_step ||
                    'Review surrounding packets in Packet Explorer, correlate source IP with known host assets, and confirm whether communication matches expected application baseline.'}
                </div>
              </div>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};

export default Timeline;
