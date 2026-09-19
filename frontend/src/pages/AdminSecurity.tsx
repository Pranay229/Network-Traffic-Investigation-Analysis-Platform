import React, { useEffect, useState } from 'react';
import { CheckCircle2, AlertTriangle, RefreshCw, UserCheck, UserX, Trash2, Search, Lock } from 'lucide-react';
import type { AdminUser } from '../types';
import {
  getAdminUsers,
  updateUserRole,
  updateUserStatus,
  revokeUserSessionsAdmin,
  getSecuritySettings,
  updateSecuritySettings
} from '../services/api';
import { SectionHeader, Card, Tabs, LoadingSpinner, ConfirmModal } from '../components/UI';

export const AdminSecurity: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'users' | 'settings'>('users');
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [search, setSearch] = useState('');
  const [confirmAction, setConfirmAction] = useState<{
    title: string;
    message: string;
    onConfirm: () => void;
  } | null>(null);

  const [formSettings, setFormSettings] = useState<{
    access_token_expire_minutes: number;
    refresh_token_expire_days: number;
    max_login_attempts: number;
    lockout_duration_minutes: number;
    max_pcap_size_mb: number;
  }>({
    access_token_expire_minutes: 15,
    refresh_token_expire_days: 7,
    max_login_attempts: 5,
    lockout_duration_minutes: 15,
    max_pcap_size_mb: 500,
  });

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [usersData, settingsData] = await Promise.all([
        getAdminUsers({ search: search || undefined }),
        getSecuritySettings(),
      ]);
      setUsers(usersData);
      setFormSettings({
        access_token_expire_minutes: settingsData.access_token_expire_minutes,
        refresh_token_expire_days: settingsData.refresh_token_expire_days,
        max_login_attempts: settingsData.max_login_attempts,
        lockout_duration_minutes: settingsData.lockout_duration_minutes,
        max_pcap_size_mb: settingsData.max_pcap_size_mb,
      });
    } catch (err: any) {
      setMessage({ type: 'error', text: err.response?.data?.detail || 'Failed to fetch admin data.' });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [search]);

  const handleRoleChange = async (userId: number, newRole: string) => {
    try {
      const updated = await updateUserRole(userId, newRole);
      setUsers(users.map((u) => (u.id === userId ? { ...u, role: updated.role } : u)));
      setMessage({ type: 'success', text: `Role updated to ${newRole} for ${updated.email}` });
    } catch (err: any) {
      setMessage({ type: 'error', text: err.response?.data?.detail || 'Failed to update role.' });
    }
  };

  const handleStatusToggle = (userId: number, currentStatus: boolean, email: string) => {
    const action = currentStatus ? 'deactivate' : 'activate';
    setConfirmAction({
      title: `${action.charAt(0).toUpperCase() + action.slice(1)} Analyst Account`,
      message: `Are you sure you want to ${action} access for ${email}?`,
      onConfirm: async () => {
        setConfirmAction(null);
        try {
          const updated = await updateUserStatus(userId, !currentStatus);
          setUsers(users.map((u) => (u.id === userId ? { ...u, is_active: updated.is_active } : u)));
          setMessage({ type: 'success', text: `Account for ${email} is now ${updated.is_active ? 'Active' : 'Deactivated'}.` });
        } catch (err: any) {
          setMessage({ type: 'error', text: err.response?.data?.detail || 'Failed to update status.' });
        }
      },
    });
  };

  const handleRevokeSessions = (userId: number, email: string) => {
    setConfirmAction({
      title: 'Revoke Active User Sessions',
      message: `Revoke all active browser sessions for ${email}? The user will be immediately logged out.`,
      onConfirm: async () => {
        setConfirmAction(null);
        try {
          const res = await revokeUserSessionsAdmin(userId);
          setMessage({ type: 'success', text: res.message });
          fetchData();
        } catch (err: any) {
          setMessage({ type: 'error', text: err.response?.data?.detail || 'Failed to revoke sessions.' });
        }
      },
    });
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await updateSecuritySettings(formSettings);
      setMessage({ type: 'success', text: 'Security policies updated successfully.' });
    } catch (err: any) {
      setMessage({ type: 'error', text: err.response?.data?.detail || 'Failed to update settings.' });
    }
  };

  return (
    <div className="fade-in space-y-4 max-w-6xl mx-auto">
      <SectionHeader
        title="Security Administration"
        subtitle="User RBAC assignments, session revocation, and platform security policies"
        icon={<Lock size={18} />}
        actions={
          <button className="btn-ghost" onClick={fetchData} style={{ fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        }
      />

      <Tabs
        tabs={[
          { id: 'users', label: 'Analyst & User Management', count: users.length },
          { id: 'settings', label: 'Authentication & Security Policies' },
        ]}
        activeTab={activeTab}
        onChange={(t) => setActiveTab(t as any)}
      />

      {message && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 14px',
            background: message.type === 'success' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            border: `1px solid ${message.type === 'success' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
            borderRadius: 8,
            color: message.type === 'success' ? 'var(--success)' : 'var(--danger)',
            fontSize: 12.5,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {message.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
            <span>{message.text}</span>
          </div>
          <button onClick={() => setMessage(null)} style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: 11 }}>
            Dismiss
          </button>
        </div>
      )}

      {activeTab === 'users' && (
        <div className="space-y-4">
          <Card>
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
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search user by name or email..."
                className="soc-input"
                style={{ paddingLeft: 30 }}
              />
            </div>
          </Card>

          <Card style={{ padding: 0 }}>
            {isLoading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
                <LoadingSpinner size={30} />
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>User Identity</th>
                    <th style={{ width: 140 }}>Role</th>
                    <th style={{ width: 110 }}>Status</th>
                    <th style={{ width: 100 }}>Email Verified</th>
                    <th style={{ width: 110 }}>Active Sessions</th>
                    <th style={{ width: 130 }}>Last Login</th>
                    <th style={{ width: 120 }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 12.5 }}>
                          {u.full_name}
                        </div>
                        <div style={{ color: 'var(--text-muted)', fontFamily: 'JetBrains Mono', fontSize: 11 }}>
                          {u.email}
                        </div>
                      </td>
                      <td>
                        <select
                          value={u.role}
                          onChange={(e) => handleRoleChange(u.id, e.target.value)}
                          className="soc-input"
                          style={{ padding: '3px 8px', fontSize: 11.5, fontFamily: 'JetBrains Mono' }}
                        >
                          <option value="ADMIN">ADMIN</option>
                          <option value="ANALYST">ANALYST</option>
                          <option value="VIEWER">VIEWER</option>
                        </select>
                      </td>
                      <td>
                        <span
                          style={{
                            padding: '2px 7px',
                            borderRadius: 4,
                            fontSize: 10.5,
                            fontWeight: 700,
                            fontFamily: 'JetBrains Mono',
                            textTransform: 'uppercase',
                            background: u.is_active ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                            color: u.is_active ? 'var(--success)' : 'var(--danger)',
                            border: `1px solid ${u.is_active ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                          }}
                        >
                          {u.is_active ? 'Active' : 'Disabled'}
                        </span>
                      </td>
                      <td>
                        {u.is_email_verified ? (
                          <span style={{ color: 'var(--success)', fontSize: 11, fontWeight: 600 }}>Yes</span>
                        ) : (
                          <span style={{ color: 'var(--warning)', fontSize: 11 }}>Unverified</span>
                        )}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                        {u.active_sessions_count}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                        {u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : 'Never'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button
                            onClick={() => handleStatusToggle(u.id, u.is_active, u.email)}
                            className={u.is_active ? 'btn-danger' : 'btn-ghost'}
                            style={{ padding: '4px 8px', fontSize: 11 }}
                            title={u.is_active ? 'Deactivate Account' : 'Activate Account'}
                          >
                            {u.is_active ? <UserX size={12} /> : <UserCheck size={12} />}
                          </button>
                          <button
                            onClick={() => handleRevokeSessions(u.id, u.email)}
                            className="btn-ghost"
                            style={{ padding: '4px 8px', fontSize: 11 }}
                            title="Revoke active sessions"
                          >
                            <Trash2 size={12} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {users.length === 0 && (
                    <tr>
                      <td colSpan={7} style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>
                        No user accounts match search query.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </Card>
        </div>
      )}

      {activeTab === 'settings' && (
        <Card style={{ maxWidth: 680 }}>
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Authentication & Security Policies
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
            Configure session limits, brute-force lockout thresholds, and token lifecycles.
          </div>

          <form onSubmit={handleSaveSettings} className="space-y-4">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                  Access Token Expiry (Minutes)
                </label>
                <input
                  type="number"
                  min="1"
                  max="1440"
                  value={formSettings.access_token_expire_minutes}
                  onChange={(e) =>
                    setFormSettings({ ...formSettings, access_token_expire_minutes: parseInt(e.target.value) || 15 })
                  }
                  className="soc-input"
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                  Refresh Session Duration (Days)
                </label>
                <input
                  type="number"
                  min="1"
                  max="90"
                  value={formSettings.refresh_token_expire_days}
                  onChange={(e) =>
                    setFormSettings({ ...formSettings, refresh_token_expire_days: parseInt(e.target.value) || 7 })
                  }
                  className="soc-input"
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                  Max Failed Login Attempts
                </label>
                <input
                  type="number"
                  min="3"
                  max="20"
                  value={formSettings.max_login_attempts}
                  onChange={(e) =>
                    setFormSettings({ ...formSettings, max_login_attempts: parseInt(e.target.value) || 5 })
                  }
                  className="soc-input"
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                  Lockout Duration (Minutes)
                </label>
                <input
                  type="number"
                  min="1"
                  max="1440"
                  value={formSettings.lockout_duration_minutes}
                  onChange={(e) =>
                    setFormSettings({ ...formSettings, lockout_duration_minutes: parseInt(e.target.value) || 15 })
                  }
                  className="soc-input"
                />
              </div>

              <div style={{ gridColumn: 'span 2' }}>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                  Max PCAP Upload Size (MB)
                </label>
                <input
                  type="number"
                  min="5"
                  max="1000"
                  value={formSettings.max_pcap_size_mb}
                  onChange={(e) =>
                    setFormSettings({ ...formSettings, max_pcap_size_mb: parseInt(e.target.value) || 500 })
                  }
                  className="soc-input"
                />
              </div>
            </div>

            <div style={{ paddingTop: 8 }}>
              <button type="submit" className="btn-primary" style={{ padding: '8px 18px', fontSize: 13 }}>
                Save Security Policies
              </button>
            </div>
          </form>
        </Card>
      )}

      {confirmAction && (
        <ConfirmModal
          title={confirmAction.title}
          message={confirmAction.message}
          onConfirm={confirmAction.onConfirm}
          onCancel={() => setConfirmAction(null)}
          confirmLabel="Execute"
          danger
        />
      )}
    </div>
  );
};

export default AdminSecurity;
