import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload, FileText, CheckCircle2, AlertTriangle, Loader2,
  Shield, Lock, ArrowRight, HardDrive, FileCode, Check
} from 'lucide-react';
import { SectionHeader, Card, ProgressBar } from '../components/UI';
import { uploadPCAP, formatBytes } from '../services/api';

type UploadStage = 'idle' | 'uploading' | 'parsing' | 'analyzing' | 'detection' | 'complete' | 'error';

export const UploadPage: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [stage, setStage] = useState<UploadStage>('idle');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [invId, setInvId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const navigate = useNavigate();

  const handleFile = (f: File) => {
    const ext = f.name.split('.').pop()?.toLowerCase();
    if (!['pcap', 'pcapng'].includes(ext || '')) {
      setError(`Unsupported file extension ".${ext}". Please provide a .pcap or .pcapng network capture file.`);
      return;
    }
    if (f.size > 500 * 1024 * 1024) {
      setError('File exceeds maximum upload limit of 500 MB.');
      return;
    }
    setFile(f);
    setError(null);
    setStage('idle');
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) handleFile(f);
  };

  const handleUpload = async () => {
    if (!file) return;
    setStage('uploading');
    setUploadProgress(0);
    setError(null);

    try {
      const result = await uploadPCAP(file, (pct) => {
        setUploadProgress(pct);
        if (pct >= 100) {
          setStage('parsing');
        }
      });

      setInvId(result.inv_id);
      localStorage.setItem('selected_inv', result.inv_id);

      // Simulating visual stage transitions while backend processes in background
      setTimeout(() => setStage('analyzing'), 800);
      setTimeout(() => setStage('detection'), 1600);
      setTimeout(() => setStage('complete'), 2400);
    } catch (err: any) {
      setStage('error');
      const msg = err?.response?.data?.detail || 'Failed to upload PCAP. Please verify file integrity and server status.';
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
  };

  const pipelineStages: Array<{ key: UploadStage; label: string; desc: string }> = [
    { key: 'uploading', label: 'UPLOAD', desc: 'Secure transfer to SOC analysis buffer' },
    { key: 'parsing', label: 'PARSING', desc: 'Dissecting frames, headers & protocols' },
    { key: 'analyzing', label: 'ANALYZING', desc: 'Aggregating hosts, flows, DNS & HTTP' },
    { key: 'detection', label: 'DETECTION', desc: 'Evaluating heuristic threat rules & IOCs' },
    { key: 'complete', label: 'COMPLETE', desc: 'Investigation database ready' },
  ];

  const getStageIndex = (s: UploadStage) => {
    if (s === 'uploading') return 0;
    if (s === 'parsing') return 1;
    if (s === 'analyzing') return 2;
    if (s === 'detection') return 3;
    if (s === 'complete') return 4;
    return -1;
  };

  const currentIdx = getStageIndex(stage);

  return (
    <div className="fade-in space-y-5">
      <SectionHeader
        title="Upload PCAP"
        subtitle="Ingest packet captures for automated deep packet analysis and anomaly detection"
        icon={<Upload size={18} />}
      />

      <div style={{ maxWidth: 740, margin: '0 auto' }}>
        {/* Drag & Drop Upload Panel */}
        <Card style={{ marginBottom: 18 }}>
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => {
              if (stage === 'idle' || stage === 'error') {
                document.getElementById('pcap-file-input')?.click();
              }
            }}
            style={{
              border: `2px dashed ${
                dragging
                  ? 'var(--accent)'
                  : file
                  ? 'var(--success)'
                  : 'var(--border)'
              }`,
              borderRadius: 8,
              padding: '44px 24px',
              textAlign: 'center',
              cursor: stage === 'idle' || stage === 'error' ? 'pointer' : 'default',
              transition: 'all 0.15s ease',
              background: dragging
                ? 'var(--accent-glow)'
                : file
                ? 'rgba(16, 185, 129, 0.04)'
                : 'var(--bg-secondary)',
            }}
          >
            <input
              id="pcap-file-input"
              type="file"
              accept=".pcap,.pcapng"
              style={{ display: 'none' }}
              onChange={handleChange}
              disabled={stage !== 'idle' && stage !== 'error'}
            />

            {!file ? (
              <div className="flex flex-col items-center">
                <div
                  style={{
                    width: 52,
                    height: 52,
                    borderRadius: '50%',
                    background: 'rgba(6, 182, 212, 0.1)',
                    border: '1px solid rgba(6, 182, 212, 0.25)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent)',
                    marginBottom: 14,
                  }}
                >
                  <Upload size={24} />
                </div>
                <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                  Upload PCAP
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12 }}>
                  Drag & drop your file or <span style={{ color: 'var(--accent)', textDecoration: 'underline' }}>Browse Files</span>
                </div>
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '3px 10px',
                    background: 'rgba(255, 255, 255, 0.04)',
                    border: '1px solid var(--border)',
                    borderRadius: 20,
                    fontSize: 11,
                    fontFamily: 'JetBrains Mono',
                    color: 'var(--text-muted)',
                  }}
                >
                  <FileCode size={12} />
                  .pcap / .pcapng
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center">
                <div
                  style={{
                    width: 52,
                    height: 52,
                    borderRadius: '50%',
                    background: 'rgba(16, 185, 129, 0.1)',
                    border: '1px solid rgba(16, 185, 129, 0.25)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--success)',
                    marginBottom: 14,
                  }}
                >
                  <FileText size={24} />
                </div>
                <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  {file.name}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {formatBytes(file.size)} · {stage === 'idle' ? 'Click to change file' : 'Captured Packet Data'}
                </div>
              </div>
            )}
          </div>

          {/* Technical Specs & Security Notice */}
          <div
            style={{
              marginTop: 14,
              padding: '12px 14px',
              background: 'rgba(255, 255, 255, 0.02)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 6,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: 11.5,
              color: 'var(--text-muted)',
              flexWrap: 'wrap',
              gap: 8,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <HardDrive size={13} color="var(--accent)" />
              <span>Max file size: <strong className="text-slate-300 font-mono">500 MB</strong></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Shield size={13} color="#34d399" />
              <span>Supported formats: <strong className="text-slate-300 font-mono">.pcap, .pcapng</strong></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Lock size={13} color="#f59e0b" />
              <span>Files are processed locally by the analysis engine.</span>
            </div>
          </div>
        </Card>

        {/* Upload Progress & Stepper Pipeline */}
        {stage !== 'idle' && (
          <Card style={{ marginBottom: 18 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 14 }}>
              Analysis Pipeline Progression
            </div>

            {/* Step Pipeline Visualization */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8, marginBottom: 16 }}>
              {pipelineStages.map((st, i) => {
                const isCompleted = currentIdx > i;
                const isCurrent = currentIdx === i;
                return (
                  <div
                    key={st.key}
                    style={{
                      padding: '10px 8px',
                      borderRadius: 6,
                      background: isCurrent
                        ? 'rgba(6, 182, 212, 0.1)'
                        : isCompleted
                        ? 'rgba(16, 185, 129, 0.08)'
                        : 'var(--bg-secondary)',
                      border: `1px solid ${
                        isCurrent
                          ? 'var(--accent)'
                          : isCompleted
                          ? 'rgba(16, 185, 129, 0.3)'
                          : 'var(--border)'
                      }`,
                      textAlign: 'center',
                    }}
                  >
                    <div
                      style={{
                        width: 20,
                        height: 20,
                        borderRadius: '50%',
                        margin: '0 auto 6px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        background: isCurrent
                          ? 'var(--accent)'
                          : isCompleted
                          ? 'var(--success)'
                          : 'var(--border)',
                        color: 'white',
                        fontSize: 10,
                        fontWeight: 700,
                      }}
                    >
                      {isCompleted ? <Check size={11} /> : isCurrent ? <Loader2 size={11} className="animate-spin" /> : i + 1}
                    </div>
                    <div
                      style={{
                        fontSize: 10.5,
                        fontWeight: 700,
                        fontFamily: 'JetBrains Mono',
                        color: isCurrent
                          ? 'var(--accent)'
                          : isCompleted
                          ? 'var(--success)'
                          : 'var(--text-muted)',
                      }}
                    >
                      {st.label}
                    </div>
                  </div>
                );
              })}
            </div>

            {stage === 'uploading' && (
              <ProgressBar value={uploadProgress} label={`Streaming PCAP payload (${uploadProgress}%)`} />
            )}

            {stage === 'complete' && (
              <div
                style={{
                  marginTop: 14,
                  padding: 14,
                  background: 'rgba(16, 185, 129, 0.08)',
                  border: '1px solid rgba(16, 185, 129, 0.25)',
                  borderRadius: 8,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: 10,
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--success)', fontSize: 13, fontWeight: 700 }}>
                    <CheckCircle2 size={16} /> PCAP Dissection Complete
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>
                    Investigation ID: <strong style={{ color: 'var(--accent)' }}>{invId}</strong>
                  </div>
                </div>
                <button className="btn-primary" onClick={() => navigate('/')}>
                  Open Investigation Overview <ArrowRight size={13} />
                </button>
              </div>
            )}
          </Card>
        )}

        {/* Error Notification */}
        {error && (
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 10,
              padding: 14,
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: 8,
              marginBottom: 16,
              color: '#f87171',
              fontSize: 12.5,
            }}
          >
            <AlertTriangle size={16} className="shrink-0 mt-0.5" />
            <div>{error}</div>
          </div>
        )}

        {/* Action Button */}
        {file && (stage === 'idle' || stage === 'error') && (
          <button
            className="btn-primary"
            onClick={handleUpload}
            style={{ width: '100%', justifyContent: 'center', padding: '11px', fontSize: 13.5 }}
          >
            <Upload size={15} /> Initiate PCAP Analysis Pipeline
          </button>
        )}
      </div>
    </div>
  );
};

export default UploadPage;
