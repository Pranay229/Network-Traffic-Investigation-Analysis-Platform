import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import MainLayout from './layouts/MainLayout';

// Investigation Pages
import Overview from './pages/Overview';
import Upload from './pages/Upload';
import Investigations from './pages/Investigations';
import Traffic from './pages/Traffic';
import Hosts from './pages/Hosts';
import Conversations from './pages/Conversations';
import DNS from './pages/DNS';
import HTTP from './pages/HTTP';
import TCP from './pages/TCP';
import ICMPPage from './pages/ICMP';
import Alerts from './pages/Alerts';
import Timeline from './pages/Timeline';
import PacketExplorer from './pages/PacketExplorer';
import IOCExplorer from './pages/IOCExplorer';
import Reports from './pages/Reports';
import SettingsPage from './pages/SettingsPage';
import NetworkScanner from './pages/NetworkScanner';
import Protocols from './pages/Protocols';
import { AdminSecurity } from './pages/AdminSecurity';
import { AuditLogs } from './pages/AuditLogs';

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Legacy Auth Route Redirects */}
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="/register" element={<Navigate to="/" replace />} />
          <Route path="/verify-email" element={<Navigate to="/" replace />} />
          <Route path="/forgot-password" element={<Navigate to="/" replace />} />
          <Route path="/reset-password" element={<Navigate to="/" replace />} />
          <Route path="/profile" element={<Navigate to="/" replace />} />
          <Route path="/change-password" element={<Navigate to="/" replace />} />
          <Route path="/sessions" element={<Navigate to="/" replace />} />

          {/* Open Access Application Layout & Routes */}
          <Route path="/" element={<MainLayout />}>
            <Route index element={<Overview />} />
            <Route path="dashboard" element={<Overview />} />
            <Route path="upload" element={<Upload />} />
            <Route path="investigations" element={<Investigations />} />
            <Route path="traffic" element={<Traffic />} />
            <Route path="hosts" element={<Hosts />} />
            <Route path="conversations" element={<Conversations />} />
            <Route path="dns" element={<DNS />} />
            <Route path="http" element={<HTTP />} />
            <Route path="tcp" element={<TCP />} />
            <Route path="icmp" element={<ICMPPage />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="timeline" element={<Timeline />} />
            <Route path="packets" element={<PacketExplorer />} />
            <Route path="iocs" element={<IOCExplorer />} />
            <Route path="reports" element={<Reports />} />
            <Route path="protocols" element={<Protocols />} />
            <Route path="scanner" element={<NetworkScanner />} />
            <Route path="scans" element={<NetworkScanner />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="admin" element={<AdminSecurity />} />
            <Route path="audit-logs" element={<AuditLogs />} />
          </Route>

          {/* Catch-all fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
