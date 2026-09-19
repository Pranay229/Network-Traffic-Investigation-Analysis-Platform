import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Upload, FolderOpen, Activity, Monitor, MessageSquare,
  Globe, Server, AlertTriangle, Clock, Search, Crosshair, FileText,
  Settings, ChevronLeft, ChevronRight, Wifi, Terminal, Lock, ShieldAlert,
  Radio, Radar, Layers
} from 'lucide-react';

interface NavItem {
  path: string;
  label: string;
  icon: React.ReactNode;
  group: 'INVESTIGATE' | 'NETWORK' | 'DETECTION' | 'REPORTING' | 'ADMINISTRATION';
  adminOnly?: boolean;
  hideForViewer?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  // INVESTIGATE
  { path: '/', label: 'Overview', icon: <Activity size={15} />, group: 'INVESTIGATE' },
  { path: '/investigations', label: 'Investigations', icon: <FolderOpen size={15} />, group: 'INVESTIGATE' },
  { path: '/upload', label: 'Upload PCAP', icon: <Upload size={15} />, group: 'INVESTIGATE', hideForViewer: true },
  { path: '/packets', label: 'Packet Explorer', icon: <Search size={15} />, group: 'INVESTIGATE' },
  { path: '/traffic', label: 'Traffic Analysis', icon: <Wifi size={15} />, group: 'INVESTIGATE' },

  // NETWORK
  { path: '/protocols', label: 'Protocols', icon: <Layers size={15} />, group: 'NETWORK' },
  { path: '/scanner', label: 'Network Scanner', icon: <Radar size={15} />, group: 'NETWORK' },
  { path: '/hosts', label: 'Hosts', icon: <Monitor size={15} />, group: 'NETWORK' },
  { path: '/conversations', label: 'Conversations', icon: <MessageSquare size={15} />, group: 'NETWORK' },
  { path: '/dns', label: 'DNS', icon: <Globe size={15} />, group: 'NETWORK' },
  { path: '/http', label: 'HTTP', icon: <Server size={15} />, group: 'NETWORK' },
  { path: '/tcp', label: 'TCP', icon: <Terminal size={15} />, group: 'NETWORK' },
  { path: '/icmp', label: 'ICMP', icon: <Radio size={15} />, group: 'NETWORK' },

  // DETECTION
  { path: '/alerts', label: 'Alerts', icon: <AlertTriangle size={15} />, group: 'DETECTION' },
  { path: '/timeline', label: 'Timeline', icon: <Clock size={15} />, group: 'DETECTION' },
  { path: '/iocs', label: 'IOC Explorer', icon: <Crosshair size={15} />, group: 'DETECTION' },

  // REPORTING
  { path: '/reports', label: 'Reports', icon: <FileText size={15} />, group: 'REPORTING' },

  // ADMINISTRATION
  { path: '/admin', label: 'Admin Panel', icon: <Lock size={15} />, group: 'ADMINISTRATION', adminOnly: true },
  { path: '/audit-logs', label: 'Audit Logs', icon: <ShieldAlert size={15} />, group: 'ADMINISTRATION', adminOnly: true },
  { path: '/settings', label: 'Settings', icon: <Settings size={15} />, group: 'ADMINISTRATION' },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen?: boolean;
  onMobileClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed,
  onToggle,
  mobileOpen,
  onMobileClose,
}) => {
  const location = useLocation();

  const groups: Array<'INVESTIGATE' | 'NETWORK' | 'DETECTION' | 'REPORTING' | 'ADMINISTRATION'> = [
    'INVESTIGATE',
    'NETWORK',
    'DETECTION',
    'REPORTING',
    'ADMINISTRATION',
  ];

  const sidebarContent = (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        background: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border)',
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          padding: collapsed ? '14px 10px' : '16px 14px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          minHeight: 58,
        }}
      >
        <div
          style={{
            width: 32,
            height: 32,
            minWidth: 32,
            background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.18), rgba(2, 132, 199, 0.25))',
            border: '1px solid rgba(6, 182, 212, 0.4)',
            borderRadius: 8,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 14px rgba(6, 182, 212, 0.25)',
            padding: 3,
            flexShrink: 0,
          }}
        >
          <img
            src="/logo.png"
            alt="Nova Cyber Spark"
            style={{
              width: '100%',
              height: '100%',
              objectFit: 'contain',
              filter: 'drop-shadow(0 0 6px rgba(6, 182, 212, 0.6)) brightness(1.1)',
            }}
          />
        </div>
        {!collapsed && (
          <div style={{ overflow: 'hidden' }}>
            <div
              style={{
                fontSize: 12,
                fontWeight: 800,
                color: 'var(--text-primary)',
                fontFamily: 'JetBrains Mono, monospace',
                letterSpacing: '0.04em',
                lineHeight: 1.1,
              }}
            >
              NOVA CYBER SPARK
            </div>
            <div
              style={{
                fontSize: 9.5,
                color: 'var(--text-muted)',
                whiteSpace: 'nowrap',
                letterSpacing: '0.02em',
              }}
            >
              Network Forensic SOC
            </div>
          </div>
        )}
      </div>

      {/* Navigation List */}
      <nav
        style={{
          flex: 1,
          padding: '12px 8px',
          overflowY: 'auto',
          overflowX: 'hidden',
        }}
      >
        {groups.map((group) => {
          const items = NAV_ITEMS.filter((i) => i.group === group);

          if (items.length === 0) return null;

          return (
            <div key={group} style={{ marginBottom: 14 }}>
              {!collapsed && (
                <div
                  style={{
                    fontSize: 9.5,
                    fontWeight: 700,
                    letterSpacing: '0.08em',
                    color: 'var(--text-dim)',
                    textTransform: 'uppercase',
                    padding: '0 8px 5px',
                    fontFamily: 'JetBrains Mono, monospace',
                  }}
                >
                  {group}
                </div>
              )}
              {items.map((item) => {
                const isActive =
                  item.path === '/'
                    ? location.pathname === '/'
                    : location.pathname.startsWith(item.path);

                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={`sidebar-nav-item ${isActive ? 'active' : ''}`}
                    title={collapsed ? item.label : undefined}
                    onClick={() => {
                      if (onMobileClose) onMobileClose();
                    }}
                    style={{
                      justifyContent: collapsed ? 'center' : undefined,
                      padding: collapsed ? '9px 0' : '7.5px 10px',
                      marginBottom: 2,
                    }}
                  >
                    <span
                      style={{
                        minWidth: 15,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      {item.icon}
                    </span>
                    {!collapsed && (
                      <span
                        style={{
                          whiteSpace: 'nowrap',
                          fontSize: 12,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {item.label}
                      </span>
                    )}
                  </NavLink>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Attribution & Collapse Footer Bar */}
      {!collapsed && (
        <div
          style={{
            padding: '8px 10px 6px',
            borderTop: '1px solid var(--border)',
            textAlign: 'center',
            background: 'rgba(0, 0, 0, 0.2)',
          }}
        >
          <div
            style={{
              fontSize: 9.5,
              fontWeight: 700,
              color: 'var(--text-secondary)',
              letterSpacing: '0.04em',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            NOVA CYBER SPARK™
          </div>
          <div style={{ fontSize: 8.5, color: 'var(--text-dim)', marginTop: 2, lineHeight: 1.3 }}>
            Founder: <strong style={{ color: 'var(--text-muted)' }}>Pranay Kumar Mallem</strong>
          </div>
          <div style={{ fontSize: 7.5, color: 'var(--text-dim)', opacity: 0.8, marginTop: 1 }}>
            All Patents & Rights Reserved
          </div>
        </div>
      )}

      <div
        style={{
          padding: '8px',
          borderTop: collapsed ? '1px solid var(--border)' : 'none',
          display: 'flex',
          justifyContent: 'center',
        }}
      >
        <button
          onClick={onToggle}
          style={{
            width: '100%',
            padding: '6px',
            background: 'transparent',
            border: '1px solid var(--border)',
            borderRadius: 6,
            color: 'var(--text-muted)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            transition: 'all 0.15s ease',
          }}
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop / Laptop Sidebar */}
      <aside
        style={{
          width: collapsed ? 56 : 210,
          minWidth: collapsed ? 56 : 210,
          height: '100%',
          transition: 'width 0.2s ease, min-width 0.2s ease',
          position: 'relative',
          zIndex: 30,
        }}
        className="hidden md:block"
      >
        {sidebarContent}
      </aside>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-50 md:hidden flex"
          style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(3px)' }}
          onClick={onMobileClose}
        >
          <div
            style={{ width: 240, height: '100%' }}
            onClick={(e) => e.stopPropagation()}
          >
            {sidebarContent}
          </div>
        </div>
      )}
    </>
  );
};

export default Sidebar;
