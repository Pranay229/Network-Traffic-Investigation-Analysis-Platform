import React, { useState, useEffect } from 'react';
import { X, Server, CheckCircle2, AlertCircle, RefreshCw, ExternalLink, Globe, Laptop } from 'lucide-react';
import { getApiBaseUrl, setCustomApiUrl, testApiUrl } from '../services/api';

interface ApiConnectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConnected?: () => void;
}

export const ApiConnectModal: React.FC<ApiConnectModalProps> = ({ isOpen, onClose, onConnected }) => {
  const [urlInput, setUrlInput] = useState('');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string; version?: string; tshark?: boolean } | null>(null);

  useEffect(() => {
    if (isOpen) {
      const current = getApiBaseUrl().replace(/\/api\/?$/, '');
      setUrlInput(current === '/api' ? '' : current);
      setTestResult(null);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleTestAndSave = async (candidate?: string) => {
    const target = (candidate !== undefined ? candidate : urlInput).trim();
    setTesting(true);
    setTestResult(null);

    // If empty, test default
    const testTarget = target || (typeof window !== 'undefined' ? window.location.origin : '');
    const res = await testApiUrl(testTarget);
    setTestResult(res);
    setTesting(false);

    if (res.ok) {
      setCustomApiUrl(target || null);
      if (onConnected) onConnected();
      setTimeout(() => {
        onClose();
      }, 1200);
    }
  };

  const handleReset = () => {
    setCustomApiUrl(null);
    setUrlInput('');
    setTestResult(null);
    if (onConnected) onConnected();
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 50,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0, 0, 0, 0.75)',
        backdropFilter: 'blur(4px)',
        padding: 16,
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 540,
          background: 'var(--bg-secondary, #0d1117)',
          border: '1px solid var(--border, #30363d)',
          borderRadius: 12,
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
          overflow: 'hidden',
          animation: 'fadeIn 0.15s ease-out',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '16px 20px',
            borderBottom: '1px solid var(--border, #30363d)',
            background: 'var(--bg-tertiary, #161b22)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div
              style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                background: 'rgba(6, 182, 212, 0.12)',
                border: '1px solid rgba(6, 182, 212, 0.25)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent, #06b6d4)',
              }}
            >
              <Server size={18} />
            </div>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary, #f0f6fc)' }}>
                Backend API Connection
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted, #8b949e)' }}>
                Connect your Netlify frontend to the Python analysis engine
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted, #8b949e)',
              cursor: 'pointer',
              padding: 4,
            }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div style={{ padding: 20 }}>
          <div
            style={{
              padding: '12px 14px',
              borderRadius: 8,
              background: 'rgba(56, 189, 248, 0.08)',
              border: '1px solid rgba(56, 189, 248, 0.2)',
              fontSize: 12,
              lineHeight: 1.5,
              color: '#93c5fd',
              marginBottom: 16,
            }}
          >
            <strong>Why is it showing OFFLINE?</strong> Netlify hosts the React user interface statically. The packet
            analysis engine requires your Python/FastAPI backend running on <strong>Render</strong> (or locally).
          </div>

          <label
            style={{
              display: 'block',
              fontSize: 11.5,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              color: 'var(--text-muted, #8b949e)',
              marginBottom: 6,
            }}
          >
            Python Backend URL
          </label>

          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="e.g. https://nova-cyber-spark-api.onrender.com"
              style={{
                flex: 1,
                padding: '9px 12px',
                borderRadius: 6,
                background: 'var(--bg-primary, #090d13)',
                border: '1px solid var(--border, #30363d)',
                color: 'var(--text-primary, #f0f6fc)',
                fontSize: 12.5,
                fontFamily: 'JetBrains Mono, monospace',
                outline: 'none',
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleTestAndSave();
              }}
            />
          </div>

          {/* Quick Preset Buttons */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
            <button
              type="button"
              onClick={() => {
                const promptVal = prompt('Paste your Render Service URL (e.g. https://nova-api.onrender.com):');
                if (promptVal) {
                  setUrlInput(promptVal.trim());
                  handleTestAndSave(promptVal.trim());
                }
              }}
              style={{
                padding: '5px 10px',
                borderRadius: 5,
                background: 'rgba(6, 182, 212, 0.08)',
                border: '1px solid rgba(6, 182, 212, 0.2)',
                color: 'var(--accent, #06b6d4)',
                fontSize: 11,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 5,
              }}
            >
              <Globe size={12} /> Render Cloud URL
            </button>
            <button
              type="button"
              onClick={() => {
                setUrlInput('http://localhost:8001');
                handleTestAndSave('http://localhost:8001');
              }}
              style={{
                padding: '5px 10px',
                borderRadius: 5,
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid var(--border, #30363d)',
                color: 'var(--text-secondary, #c9d1d9)',
                fontSize: 11,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 5,
              }}
            >
              <Laptop size={12} /> Localhost (port 8001)
            </button>
            <button
              type="button"
              onClick={handleReset}
              style={{
                padding: '5px 10px',
                borderRadius: 5,
                background: 'transparent',
                border: '1px dashed var(--border, #30363d)',
                color: 'var(--text-muted, #8b949e)',
                fontSize: 11,
                cursor: 'pointer',
              }}
            >
              Reset to Default
            </button>
          </div>

          {/* Test Feedback */}
          {testResult && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: 6,
                background: testResult.ok ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                border: `1px solid ${testResult.ok ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                fontSize: 12,
                color: testResult.ok ? '#34d399' : '#f87171',
                marginBottom: 16,
              }}
            >
              {testResult.ok ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
              <div style={{ flex: 1 }}>
                <div>{testResult.message}</div>
                {testResult.version && (
                  <div style={{ fontSize: 10.5, opacity: 0.8, marginTop: 2 }}>
                    API Version: v{testResult.version} | TShark: {testResult.tshark ? 'Available' : 'Not installed'}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '8px 14px',
                borderRadius: 6,
                background: 'transparent',
                border: '1px solid var(--border, #30363d)',
                color: 'var(--text-secondary, #c9d1d9)',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={testing}
              onClick={() => handleTestAndSave()}
              style={{
                padding: '8px 18px',
                borderRadius: 6,
                background: 'var(--accent, #06b6d4)',
                border: 'none',
                color: '#000',
                fontSize: 12,
                fontWeight: 700,
                cursor: testing ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              {testing ? <RefreshCw size={14} className="animate-spin" /> : <Server size={14} />}
              {testing ? 'Testing...' : 'Save & Connect'}
            </button>
          </div>
        </div>

        {/* Footer Note */}
        <div
          style={{
            padding: '10px 20px',
            background: 'var(--bg-primary, #090d13)',
            borderTop: '1px solid var(--border, #30363d)',
            fontSize: 10.5,
            color: 'var(--text-muted, #8b949e)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span>Permanent fix: add VITE_API_URL in Netlify Environment Variables.</span>
          <a
            href="https://dashboard.render.com"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: 'var(--accent, #06b6d4)', display: 'flex', alignItems: 'center', gap: 3 }}
          >
            Open Render <ExternalLink size={10} />
          </a>
        </div>
      </div>
    </div>
  );
};
