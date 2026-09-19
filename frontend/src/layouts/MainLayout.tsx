import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import TopNav from '../components/TopNav';

export const MainLayout: React.FC = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--bg-primary)' }}>
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed((c) => !c)}
        mobileOpen={mobileSidebarOpen}
        onMobileClose={() => setMobileSidebarOpen(false)}
      />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        <TopNav onMobileMenuToggle={() => setMobileSidebarOpen((o) => !o)} />
        <main
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: '20px 24px',
            background: 'var(--bg-primary)',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <div style={{ flex: 1 }}>
            <Outlet />
          </div>
          {/* Global Enterprise SOC Footer */}
          <footer
            style={{
              marginTop: 32,
              paddingTop: 14,
              borderTop: '1px solid var(--border)',
              display: 'flex',
              flexWrap: 'wrap',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: 8,
              fontSize: 11,
              color: 'var(--text-dim)',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <img src="/logo.png" alt="Nova Cyber Spark Logo" style={{ width: 18, height: 18, objectFit: 'contain', opacity: 0.9 }} />
              <span>
                <strong style={{ color: 'var(--text-secondary)' }}>NOVA CYBER SPARK™</strong> — Network Traffic Investigation & Analysis Platform
              </span>
            </div>
            <div>
              Founder: <span style={{ color: 'var(--text-muted)' }}>Pranay Kumar Mallem</span> · <span style={{ color: 'var(--accent)', opacity: 0.9 }}>All Patents & Intellectual Rights Reserved</span>
            </div>
          </footer>
        </main>
      </div>
    </div>
  );
};

export default MainLayout;
