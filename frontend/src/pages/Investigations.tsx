import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderOpen, Trash2, Eye, RefreshCw, Upload, FileCode,
  MessageSquare, Plus, CheckCircle2, AlertTriangle, Shield, Clock, Send
} from 'lucide-react';
import { SectionHeader, Card, EmptyState, LoadingSpinner, ConfirmModal } from '../components/UI';
import { StatusBadge, SeverityBadge } from '../components/Badges';
import {
  getInvestigations, deleteInvestigation, updateInvestigationStatus, addInvestigationNote, formatBytes
} from '../services/api';
import type { Investigation, AnalystNote } from '../types';

const WORKFLOW_STATUSES: Array<'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED'> = [
  'OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'
];

export const Investigations: React.FC = () => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleteTarget, setDeleteTarget] = useState<Investigation | null>(null);
  const [notesTarget, setNotesTarget] = useState<Investigation | null>(null);
  const [newNote, setNewNote] = useState('');
  const [submittingNote, setSubmittingNote] = useState(false);
  const navigate = useNavigate();

  const activeInv = localStorage.getItem('selected_inv') || '';

  const load = async () => {
    setLoading(true);
    try {
      const data = await getInvestigations();
      setInvestigations(data);
      if (notesTarget) {
        const updated = data.find(i => i.inv_id === notesTarget.inv_id);
        if (updated) setNotesTarget(updated);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleSelect = (inv: Investigation) => {
    localStorage.setItem('selected_inv', inv.inv_id);
    navigate('/');
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await deleteInvestigation(deleteTarget.inv_id);
      if (activeInv === deleteTarget.inv_id) {
        localStorage.removeItem('selected_inv');
      }
      setDeleteTarget(null);
      load();
    } catch (e) {
      console.error('Delete failed:', e);
    }
  };

  const handleStatusChange = async (invId: string, status: any) => {
    try {
      await updateInvestigationStatus(invId, status);
      load();
    } catch (e) {
      console.error('Failed to update status:', e);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!notesTarget || !newNote.trim()) return;
    setSubmittingNote(true);
    try {
      await addInvestigationNote(notesTarget.inv_id, newNote.trim());
      setNewNote('');
      load();
    } catch (e) {
      console.error('Failed to add note:', e);
    } finally {
      setSubmittingNote(false);
    }
  };

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="Investigation Workspace"
        subtitle={`${investigations.length} investigation record${investigations.length !== 1 ? 's' : ''} stored with triage workflow, evidence, and notes`}
        icon={<FolderOpen size={18} />}
        actions={
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn-ghost" onClick={load} style={{ fontSize: 12 }}>
              <RefreshCw size={13} /> Refresh
            </button>
            <button className="btn-primary" onClick={() => navigate('/upload')} style={{ fontSize: 12 }}>
              <Upload size={13} /> Upload PCAP
            </button>
          </div>
        }
      />

      <Card style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <LoadingSpinner size={30} />
          </div>
        ) : investigations.length === 0 ? (
          <EmptyState
            icon={<FolderOpen size={44} />}
            title="No Investigations Found"
            message="Upload a PCAP capture file or perform a network scan to initialize an authorized investigation."
            action={
              <button className="btn-primary" onClick={() => navigate('/upload')} style={{ marginTop: 8 }}>
                <Upload size={14} /> Upload PCAP File
              </button>
            }
          />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th style={{ width: 130 }}>Investigation ID</th>
                  <th>Evidence Source</th>
                  <th style={{ width: 140 }}>Workflow Status</th>
                  <th style={{ width: 90 }}>Severity</th>
                  <th style={{ width: 100 }}>Packets</th>
                  <th style={{ width: 100 }}>Traffic</th>
                  <th style={{ width: 80 }}>Alerts</th>
                  <th style={{ width: 90 }}>Notes</th>
                  <th style={{ width: 100 }}>Created</th>
                  <th style={{ width: 140 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {investigations.map((inv) => {
                  const isSelected = inv.inv_id === activeInv;
                  const currentWorkflow = inv.investigation_status || 'OPEN';
                  const notesCount = inv.notes?.length || 0;

                  return (
                    <tr
                      key={inv.inv_id}
                      style={{
                        background: isSelected ? 'rgba(6, 182, 212, 0.06)' : undefined,
                      }}
                    >
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          {isSelected && <span className="pulse-dot" style={{ background: 'var(--accent)' }} />}
                          <span
                            style={{
                              fontFamily: 'JetBrains Mono',
                              fontSize: 12,
                              fontWeight: 700,
                              color: 'var(--accent)',
                            }}
                          >
                            {inv.inv_id}
                          </span>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <FileCode size={15} color="var(--text-muted)" className="shrink-0" />
                          <div>
                            <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-primary)' }}>
                              {inv.filename}
                            </div>
                            <div style={{ fontSize: 10.5, color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                              {formatBytes(inv.file_size)}
                              {inv.related_scan_id && (
                                <span style={{ marginLeft: 6, color: '#06b6d4' }}>
                                  • Scan: {inv.related_scan_id}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <select
                          value={currentWorkflow}
                          onChange={(e) => handleStatusChange(inv.inv_id, e.target.value)}
                          style={{
                            fontSize: 11,
                            padding: '3px 6px',
                            borderRadius: 4,
                            background: 'var(--bg-secondary)',
                            color: currentWorkflow === 'OPEN' ? '#06b6d4' : currentWorkflow === 'RESOLVED' ? '#10b981' : '#f59e0b',
                            border: '1px solid var(--border)',
                            fontWeight: 600,
                            fontFamily: 'monospace'
                          }}
                        >
                          {WORKFLOW_STATUSES.map(st => (
                            <option key={st} value={st}>{st}</option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <SeverityBadge severity={inv.severity?.toLowerCase() || (inv.total_alerts > 0 ? 'medium' : 'low')} />
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                        {inv.total_packets.toLocaleString()}
                      </td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                        {formatBytes(inv.total_bytes)}
                      </td>
                      <td>
                        <span
                          style={{
                            fontFamily: 'JetBrains Mono',
                            fontSize: 12,
                            fontWeight: 700,
                            color: inv.total_alerts > 0 ? 'var(--danger)' : 'var(--text-muted)',
                          }}
                        >
                          {inv.total_alerts}
                        </span>
                      </td>
                      <td>
                        <button
                          onClick={() => setNotesTarget(inv)}
                          className="btn-ghost"
                          style={{ padding: '2px 6px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}
                          title="View and add analyst investigation notes"
                        >
                          <MessageSquare size={12} /> {notesCount}
                        </button>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {new Date(inv.created_at).toLocaleDateString()}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button
                            className={isSelected ? 'btn-primary' : 'btn-ghost'}
                            style={{ padding: '4px 8px', fontSize: 11 }}
                            onClick={() => handleSelect(inv)}
                            title="Set as active workspace investigation"
                          >
                            <Eye size={12} /> {isSelected ? 'Active' : 'Open'}
                          </button>
                          <button
                            className="btn-danger"
                            style={{ padding: '4px 8px', fontSize: 11 }}
                            onClick={() => setDeleteTarget(inv)}
                            title="Delete investigation"
                          >
                            <Trash2 size={12} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Analyst Notes Drawer/Modal */}
      {notesTarget && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            backdropFilter: 'blur(4px)',
            padding: 16
          }}
        >
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              width: '100%',
              maxWidth: 600,
              maxHeight: '85vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)'
            }}
          >
            <div
              style={{
                padding: '14px 18px',
                borderBottom: '1px solid var(--border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}
            >
              <div>
                <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <MessageSquare size={16} color="#06b6d4" />
                  Investigation Notes — {notesTarget.inv_id}
                </h3>
                <p style={{ margin: '2px 0 0', fontSize: 11.5, color: 'var(--text-muted)' }}>
                  SOC Analyst findings, containment steps, and case observations
                </p>
              </div>
              <button
                onClick={() => setNotesTarget(null)}
                className="btn-ghost"
                style={{ padding: 4 }}
              >
                ✕
              </button>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: 18, display: 'flex', flexDirection: 'column', gap: 12 }}>
              {notesTarget.notes && notesTarget.notes.length > 0 ? (
                notesTarget.notes.map((n, idx) => (
                  <div
                    key={n.id || idx}
                    style={{
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border)',
                      borderRadius: 6,
                      padding: '10px 14px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 11 }}>
                      <span style={{ fontWeight: 600, color: '#06b6d4' }}>
                        {n.user_email || 'Analyst'}
                      </span>
                      <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                        {n.timestamp}
                      </span>
                    </div>
                    <div style={{ fontSize: 12.5, color: 'var(--text-primary)', whiteSpace: 'pre-wrap' }}>
                      {n.note}
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ textAlign: 'center', padding: '32px 0', color: 'var(--text-muted)', fontSize: 12.5 }}>
                  No analyst notes documented yet for this case.
                </div>
              )}
            </div>

            <form onSubmit={handleAddNote} style={{ padding: '14px 18px', borderTop: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  placeholder="Type an investigation note or containment step..."
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  className="input"
                  style={{ flex: 1, fontSize: 12 }}
                  disabled={submittingNote}
                />
                <button
                  type="submit"
                  disabled={submittingNote || !newNote.trim()}
                  className="btn-primary"
                  style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}
                >
                  <Send size={13} /> Add Note
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {deleteTarget && (
        <ConfirmModal
          title="Delete Investigation"
          message={`Are you sure you want to delete investigation ${deleteTarget.inv_id} (${deleteTarget.filename})? This will remove all parsed packet traces, host intelligence, flow conversations, and generated alerts permanently.`}
          onConfirm={handleDelete}
          onCancel={() => setDeleteTarget(null)}
          confirmLabel="Delete Investigation"
          danger
        />
      )}
    </div>
  );
};

export default Investigations;
