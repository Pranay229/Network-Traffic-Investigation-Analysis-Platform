import React, { useState, useEffect } from 'react';
import {
  Monitor, Search, AlertTriangle, Server, Wifi
} from 'lucide-react';
import {
  SectionHeader, Card, KPICard, EmptyState, LoadingSpinner,
  Pagination, Drawer
} from '../components/UI';
import { ProtoChip, RoleBadge, SeverityBadge } from '../components/Badges';
import { getHosts, getHostDetail, formatBytes } from '../services/api';
import type { Host } from '../types';

export const Hosts: React.FC = () => {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState('total_packets');
  const [page, setPage] = useState(1);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [hostDetail, setHostDetail] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const invId = localStorage.getItem('selected_inv') || '';
  const pageSize = 50;

  useEffect(() => {
    if (!invId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    getHosts(invId, { search, sort_by: sortBy, page })
      .then((res) => {
        setHosts(res.hosts);
        setTotal(res.total);
      })
      .finally(() => setLoading(false));
  }, [invId, search, sortBy, page]);

  useEffect(() => {
    if (selectedIp && invId) {
      setDetailLoading(true);
      getHostDetail(invId, selectedIp)
        .then(setHostDetail)
        .catch(() => setHostDetail(null))
        .finally(() => setDetailLoading(false));
    } else {
      setHostDetail(null);
    }
  }, [selectedIp, invId]);

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Host Overview"
          subtitle="Network asset discovery and intelligence"
          icon={<Monitor size={18} />}
        />
        <Card>
          <EmptyState
            icon={<Monitor size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to discover communicate endpoints and host assets."
          />
        </Card>
      </div>
    );
  }

  // Host metrics
  const suspiciousHostsCount = hosts.filter((h) => h.alert_count > 0).length;
  const serversCount = hosts.filter((h) => h.role === 'server').length;
  const clientsCount = hosts.filter((h) => h.role === 'client').length;

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="Host Overview"
        subtitle={`${total} unique IP assets discovered across captured flows`}
        icon={<Monitor size={18} />}
      />

      {/* KPI Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
        <KPICard
          label="Total Hosts"
          value={total}
          icon={<Monitor size={18} />}
          color="#06b6d4"
          subtitle="All communicating nodes"
        />
        <KPICard
          label="Active Servers"
          value={serversCount}
          icon={<Server size={18} />}
          color="#10b981"
          subtitle="Listening services"
        />
        <KPICard
          label="Client Endpoints"
          value={clientsCount}
          icon={<Wifi size={18} />}
          color="#3b82f6"
          subtitle="Originating hosts"
        />
        <KPICard
          label="Potentially Suspicious"
          value={suspiciousHostsCount}
          icon={<AlertTriangle size={18} />}
          color={suspiciousHostsCount > 0 ? '#ef4444' : '#10b981'}
          subtitle={suspiciousHostsCount > 0 ? 'Associated with alerts' : 'No threat flags'}
        />
      </div>

      {/* Search & Sort Controls */}
      <Card>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 200, position: 'relative' }}>
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
              placeholder="Search by IP address..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
            />
          </div>
          <select
            className="soc-input"
            style={{ width: 190 }}
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            <option value="total_packets">Sort: Total Packets</option>
            <option value="total_bytes">Sort: Total Traffic</option>
            <option value="connection_count">Sort: Connection Count</option>
            <option value="unique_dest_ports">Sort: Unique Dest Ports</option>
            <option value="alert_count">Sort: Alert Count</option>
          </select>
        </div>
      </Card>

      {/* Hosts Data Table */}
      <Card style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={30} />
          </div>
        ) : hosts.length === 0 ? (
          <EmptyState
            icon={<Monitor size={40} />}
            title="No Hosts Found"
            message="No network nodes match your search criteria."
          />
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 170 }}>IP Address</th>
                  <th style={{ width: 100 }}>Role</th>
                  <th style={{ width: 110 }}>Packets</th>
                  <th style={{ width: 110 }}>Traffic</th>
                  <th style={{ width: 160 }}>Sent / Received</th>
                  <th style={{ width: 110 }}>Connections</th>
                  <th style={{ width: 110 }}>Dest Ports</th>
                  <th>Protocols</th>
                  <th style={{ width: 80 }}>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((h) => (
                  <tr
                    key={h.ip_address}
                    style={{
                      cursor: 'pointer',
                      background: selectedIp === h.ip_address ? 'rgba(6, 182, 212, 0.08)' : undefined,
                    }}
                    onClick={() => setSelectedIp(h.ip_address)}
                  >
                    <td>
                      <span
                        style={{
                          fontFamily: 'JetBrains Mono',
                          fontSize: 12.5,
                          fontWeight: 700,
                          color: 'var(--accent)',
                          textDecoration: 'underline',
                          cursor: 'pointer',
                        }}
                      >
                        {h.ip_address}
                      </span>
                    </td>
                    <td>
                      <RoleBadge role={h.role} />
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                      {h.total_packets.toLocaleString()}
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                      {formatBytes(h.total_bytes)}
                    </td>
                    <td style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--text-muted)' }}>
                      {formatBytes(h.bytes_sent)} / {formatBytes(h.bytes_received)}
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                      {h.connection_count}
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                      {h.unique_dest_ports}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {(h.protocols || []).slice(0, 4).map((p) => (
                          <ProtoChip key={p} protocol={p} />
                        ))}
                      </div>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: 'JetBrains Mono',
                          fontSize: 12,
                          fontWeight: 700,
                          color: h.alert_count > 0 ? 'var(--danger)' : 'var(--text-muted)',
                        }}
                      >
                        {h.alert_count}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div style={{ padding: '0 16px' }}>
              <Pagination
                page={page}
                pages={Math.ceil(total / pageSize)}
                total={total}
                pageSize={pageSize}
                onChange={setPage}
              />
            </div>
          </>
        )}
      </Card>

      {/* Host Intelligence Slide-Over Drawer */}
      <Drawer
        isOpen={!!selectedIp}
        onClose={() => setSelectedIp(null)}
        title="Host Intelligence"
        subtitle={`Asset Telemetry: ${selectedIp || ''}`}
        width={580}
      >
        {detailLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={32} />
          </div>
        ) : hostDetail ? (
          <div className="space-y-4">
            {/* Host Identity Card */}
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <div style={{ fontSize: 16, fontWeight: 800, fontFamily: 'JetBrains Mono', color: 'var(--accent)' }}>
                  {hostDetail.host.ip_address}
                </div>
                <RoleBadge role={hostDetail.host.role} />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 12 }}>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Total Packets</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600 }}>
                    {hostDetail.host.total_packets?.toLocaleString()}
                  </div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Total Volume</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600 }}>
                    {formatBytes(hostDetail.host.total_bytes || 0)}
                  </div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Sent / Received</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>
                    {formatBytes(hostDetail.host.bytes_sent || 0)} / {formatBytes(hostDetail.host.bytes_received || 0)}
                  </div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>Connections</div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)' }}>
                    {hostDetail.host.connection_count}
                  </div>
                </div>
              </div>
            </div>

            {/* Observed Top Ports */}
            {hostDetail.host.top_ports && hostDetail.host.top_ports.length > 0 && (
              <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
                <div style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', marginBottom: 6, letterSpacing: '0.04em' }}>
                  Targeted Ports
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {hostDetail.host.top_ports.map((port: number) => (
                    <span
                      key={port}
                      style={{
                        padding: '2px 7px',
                        borderRadius: 4,
                        background: 'rgba(6, 182, 212, 0.12)',
                        border: '1px solid rgba(6, 182, 212, 0.25)',
                        color: 'var(--accent)',
                        fontFamily: 'JetBrains Mono',
                        fontSize: 11,
                        fontWeight: 600,
                      }}
                    >
                      Port {port}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Host Alerts */}
            {hostDetail.alerts?.length > 0 && (
              <div style={{ background: 'var(--bg-secondary)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: 6, padding: 12 }}>
                <div style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--danger)', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                  Triggered Alerts ({hostDetail.alerts.length})
                </div>
                <div className="space-y-2">
                  {hostDetail.alerts.map((a: any) => (
                    <div
                      key={a.alert_id}
                      style={{
                        padding: '8px 10px',
                        background: 'rgba(239, 68, 68, 0.08)',
                        borderRadius: 4,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                          {a.alert_type || a.type}
                        </div>
                        <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                          {a.alert_id}
                        </div>
                      </div>
                      <SeverityBadge severity={a.severity} size="sm" />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Host DNS Activity */}
            {hostDetail.dns_queries?.length > 0 && (
              <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
                <div style={{ fontSize: 11.5, fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                  Queried DNS Names ({hostDetail.dns_queries.length})
                </div>
                <div className="space-y-1">
                  {hostDetail.dns_queries.slice(0, 8).map((q: any, i: number) => (
                    <div
                      key={i}
                      style={{
                        fontSize: 11,
                        fontFamily: 'JetBrains Mono',
                        color: 'var(--text-secondary)',
                        padding: '3px 0',
                        borderBottom: '1px solid var(--border-subtle)',
                      }}
                    >
                      {q.name || q.query_name}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : null}
      </Drawer>
    </div>
  );
};

export default Hosts;
