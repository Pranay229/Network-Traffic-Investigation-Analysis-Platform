import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in component tree:', error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReload = () => {
    window.location.reload();
  };

  private handleReset = () => {
    localStorage.removeItem('selected_inv');
    window.location.href = '/';
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '100vh',
            background: 'var(--bg-primary, #0a0e17)',
            color: 'var(--text-primary, #f1f5f9)',
            padding: 24,
            fontFamily: 'Inter, sans-serif',
          }}
        >
          <div
            style={{
              maxWidth: 560,
              width: '100%',
              background: 'var(--bg-card, #111827)',
              border: '1px solid var(--border, #1f2937)',
              borderRadius: 12,
              padding: 28,
              boxShadow: '0 25px 50px -12px rgba(0,0,0,0.6)',
              textAlign: 'center',
            }}
          >
            <div
              style={{
                width: 48,
                height: 48,
                borderRadius: '50%',
                background: 'rgba(239, 68, 68, 0.15)',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: 16,
              }}
            >
              <AlertTriangle size={26} color="#ef4444" />
            </div>

            <h2 style={{ fontSize: 18, fontWeight: 700, margin: '0 0 8px', color: 'var(--text-primary, #f1f5f9)' }}>
              Application Render Exception
            </h2>
            <p style={{ fontSize: 13, color: 'var(--text-muted, #94a3b8)', margin: '0 0 20px', lineHeight: 1.5 }}>
              The SOC platform encountered an unexpected runtime state. You can reload the page or clear the cached session.
            </p>

            {this.state.error && (
              <div
                style={{
                  background: 'var(--bg-secondary, #0b1120)',
                  border: '1px solid var(--border-subtle, #1e293b)',
                  borderRadius: 6,
                  padding: '10px 14px',
                  marginBottom: 20,
                  textAlign: 'left',
                  fontSize: 11.5,
                  fontFamily: 'JetBrains Mono, monospace',
                  color: '#f87171',
                  overflowX: 'auto',
                  maxHeight: 120,
                }}
              >
                {this.state.error.toString()}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
              <button
                onClick={this.handleReload}
                className="btn-primary"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '8px 16px',
                  fontSize: 12.5,
                  fontWeight: 600,
                  borderRadius: 6,
                  cursor: 'pointer',
                  border: 'none',
                  background: 'var(--accent, #06b6d4)',
                  color: '#000',
                }}
              >
                <RefreshCw size={14} /> Reload Page
              </button>
              <button
                onClick={this.handleReset}
                className="btn-ghost"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '8px 16px',
                  fontSize: 12.5,
                  fontWeight: 600,
                  borderRadius: 6,
                  cursor: 'pointer',
                  border: '1px solid var(--border, #1f2937)',
                  background: 'transparent',
                  color: 'var(--text-secondary, #cbd5e1)',
                }}
              >
                <Home size={14} /> Clear Cache & Reset
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
