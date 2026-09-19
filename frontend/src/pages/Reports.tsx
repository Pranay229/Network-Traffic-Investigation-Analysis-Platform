import React, { useState, useEffect } from 'react';
import { FileText, Download, Printer, Shield, RefreshCw, AlertTriangle } from 'lucide-react';
import { SectionHeader, Card, EmptyState, LoadingSpinner } from '../components/UI';
import { getReport } from '../services/api';

export const Reports: React.FC = () => {
  const [report, setReport] = useState<string | null>(null);
  const [invFilename, setInvFilename] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const invId = localStorage.getItem('selected_inv') || '';

  const loadReport = async () => {
    if (!invId) return;
    setLoading(true);
    setError('');
    try {
      const res = await getReport(invId);
      setReport(res.report);
      setInvFilename(res.filename);
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Failed to compile report. Ensure PCAP ingestion is finished.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (invId) {
      loadReport();
    }
  }, [invId]);

  const downloadReport = () => {
    if (!report) return;
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${invId}-investigation-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  if (!invId) {
    return (
      <div className="fade-in space-y-4">
        <SectionHeader
          title="Investigation Reports"
          subtitle="Executive and technical cybersecurity incident report generation"
          icon={<FileText size={18} />}
        />
        <Card>
          <EmptyState
            icon={<FileText size={40} />}
            title="No Investigation Selected"
            message="Select an active investigation to generate an executive report."
          />
        </Card>
      </div>
    );
  }

  return (
    <div className="fade-in space-y-4">
      <SectionHeader
        title="Investigation Report"
        subtitle={`Compiled forensic analysis for ${invId}`}
        icon={<FileText size={18} />}
        actions={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button className="btn-ghost" onClick={loadReport} disabled={loading} style={{ fontSize: 12 }}>
              <RefreshCw size={13} /> Regenerate
            </button>
            {report && (
              <>
                <button className="btn-ghost" onClick={handlePrint} style={{ fontSize: 12 }}>
                  <Printer size={13} /> Print
                </button>
                <button className="btn-primary" onClick={downloadReport} style={{ fontSize: 12 }}>
                  <Download size={13} /> Download .md
                </button>
              </>
            )}
          </div>
        }
      />

      {error && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: 14,
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 8,
            color: '#f87171',
            fontSize: 12.5,
          }}
        >
          <AlertTriangle size={16} />
          <div>{error}</div>
        </div>
      )}

      {loading ? (
        <Card>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 56, gap: 12 }}>
            <LoadingSpinner size={34} />
            <div style={{ fontSize: 12.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
              Compiling Executive & Forensic Markdown Report...
            </div>
          </div>
        </Card>
      ) : report ? (
        <Card style={{ padding: 0 }}>
          {/* Document Header Bar */}
          <div
            style={{
              padding: '12px 18px',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'var(--bg-secondary)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={15} color="var(--accent)" />
              <span style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--text-primary)' }}>
                Official Security Report Preview
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
              Source: {invFilename}
            </div>
          </div>

          {/* Document Body */}
          <div
            style={{
              padding: '32px 36px',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 12.5,
              lineHeight: 1.8,
              color: 'var(--text-secondary)',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              maxHeight: '75vh',
              overflowY: 'auto',
              background: '#070b14',
            }}
          >
            {report}
          </div>
        </Card>
      ) : (
        <Card>
          <div style={{ textAlign: 'center', padding: '48px 16px' }}>
            <FileText size={44} style={{ color: 'var(--text-dim)', margin: '0 auto 16px' }} />
            <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6, color: 'var(--text-primary)' }}>
              Report Ready for Compilation
            </div>
            <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginBottom: 20, maxWidth: 360, margin: '0 auto 20px' }}>
              Click below to compile all packet statistics, protocol distributions, host metrics, and heuristic alerts into a formal report.
            </div>
            <button className="btn-primary" onClick={loadReport}>
              <FileText size={14} /> Generate Report Now
            </button>
          </div>
        </Card>
      )}
    </div>
  );
};

export default Reports;
