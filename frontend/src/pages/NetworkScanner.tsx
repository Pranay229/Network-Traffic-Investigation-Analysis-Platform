import React, { useState, useEffect } from 'react';
import {
  Radar, Search, Download, FileText, RefreshCw, AlertTriangle,
  CheckCircle2, Info, Eye, HelpCircle, BookOpen, Layers,
  Terminal, Globe, Server, Lock, X, ShieldCheck, Clock, History
} from 'lucide-react';
import { SectionHeader, Card, KPICard, EmptyState, LoadingSpinner, Drawer } from '../components/UI';
import { SeverityBadge, ProtoChip } from '../components/Badges';
import {
  runScan, getScans, getScan, getScanResults, getScanReport, downloadScanReportPDF, getScanTimeline
} from '../services/api';
import type {
  ScanRecord, ScanResultsData, ScanPortItem, ScanEvent
} from '../types';
import {
  formatLocalDateTime, formatDuration, getLocalTimezoneName
} from '../utils/time';

export const NetworkScanner: React.FC = () => {
  const [target, setTarget] = useState('127.0.0.1');
  const [scanType, setScanType] = useState('standard');
  const [isScanning, setIsScanning] = useState(false);
  const [scansList, setScansList] = useState<ScanRecord[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [activeResults, setActiveResults] = useState<ScanResultsData | null>(null);
  
  // UI Controls
  const [scanTab, setScanTab] = useState<'findings' | 'timeline' | 'history'>('findings');
  const [scanTimeline, setScanTimeline] = useState<ScanEvent[]>([]);
  const [loadingTimeline, setLoadingTimeline] = useState<boolean>(false);
  const [beginnerMode, setBeginnerMode] = useState<boolean>(true);
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [searchFilter, setSearchFilter] = useState<string>('');
  
  // Modals & Drawers
  const [selectedPort, setSelectedPort] = useState<ScanPortItem | null>(null);
  const [whyFinding, setWhyFinding] = useState<{ title: string; reasoning: string; risk: string } | null>(null);
  const [learnMoreItem, setLearnMoreItem] = useState<{ title: string; learn_more: any } | null>(null);
  const [showReportPreview, setShowReportPreview] = useState(false);
  const [reportPreviewData, setReportPreviewData] = useState<any>(null);
  
  // PDF Download State: 'idle' | 'generating' | 'success' | 'error'
  const [pdfState, setPdfState] = useState<'idle' | 'generating' | 'success' | 'error'>('idle');
  const [pdfMessage, setPdfMessage] = useState('');

  // Load existing scans on mount
  useEffect(() => {
    loadScanHistory();
  }, []);

  const loadScanHistory = async () => {
    try {
      const list = await getScans();
      setScansList(list);
      if (list.length > 0 && !selectedScanId) {
        setSelectedScanId(list[0].scan_id);
        fetchScanData(list[0].scan_id);
      }
    } catch {
      // Ignored if empty
    }
  };

  const loadTimelineForScan = async (scanId: string) => {
    setLoadingTimeline(true);
    try {
      const tl = await getScanTimeline(scanId);
      setScanTimeline(tl.events || []);
    } catch {
      setScanTimeline([]);
    } finally {
      setLoadingTimeline(false);
    }
  };

  const fetchScanData = async (scanId: string) => {
    try {
      const data = await getScan(scanId);
      if (data.results) {
        setActiveResults(data.results);
      }
      loadTimelineForScan(scanId);
    } catch {
      // Handled
    }
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;

    setIsScanning(true);
    setPdfState('idle');
    try {
      const res = await runScan(target, scanType);
      setSelectedScanId(res.scan_id);
      setActiveResults(res.results);
      await loadScanHistory();
      await loadTimelineForScan(res.scan_id);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Scan failed to execute.');
    } finally {
      setIsScanning(false);
    }
  };

  // "Call Results" — directly loads the latest stored scan results from backend
  const handleCallResults = async () => {
    if (!selectedScanId) return;
    setIsScanning(true);
    try {
      const res = await getScanResults(selectedScanId);
      setActiveResults(res.results);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to retrieve scan results.');
    } finally {
      setIsScanning(false);
    }
  };

  // "Download PDF" — dynamically requests ReportLab PDF blob and triggers browser download
  const handleDownloadPDF = async () => {
    if (!selectedScanId) return;
    setPdfState('generating');
    setPdfMessage('Compiling ReportLab forensic PDF...');

    try {
      const blob = await downloadScanReportPDF(selectedScanId);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `Nova_Cyber_Spark_${selectedScanId}_Report.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      setPdfState('success');
      setPdfMessage('PDF downloaded successfully!');
      setTimeout(() => setPdfState('idle'), 4000);
    } catch (err: any) {
      setPdfState('error');
      setPdfMessage('Unable to generate the report. Please try again.');
    }
  };

  // "Preview Report" — loads structured report object
  const handlePreviewReport = async () => {
    if (!selectedScanId) return;
    try {
      const rep = await getScanReport(selectedScanId);
      setReportPreviewData(rep);
      setShowReportPreview(true);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to generate report preview.');
    }
  };

  // Categories list
  const categories = [
    { key: 'all', label: 'All Findings' },
    { key: 'Remote Access', label: 'Remote Access' },
    { key: 'Web Services', label: 'Web Services' },
    { key: 'File Sharing', label: 'File Sharing' },
    { key: 'Database Services', label: 'Database Services' },
    { key: 'Network Infrastructure', label: 'Network Infrastructure' },
    { key: 'Potentially Exposed Services', label: 'Potentially Exposed' },
  ];

  // Filter ports
  const filteredPorts = (activeResults?.ports || []).filter((p) => {
    if (activeCategory !== 'all' && p.category !== activeCategory) return false;
    if (searchFilter) {
      const query = searchFilter.toLowerCase();
      return (
        p.host.toLowerCase().includes(query) ||
        p.service.toLowerCase().includes(query) ||
        String(p.port).includes(query) ||
        p.risk.toLowerCase().includes(query)
      );
    }
    return true;
  });

  const selectedScan = scansList.find((s) => s.scan_id === selectedScanId);

  return (
    <div className="fade-in space-y-4 max-w-7xl mx-auto">
      {/* Header */}
      <SectionHeader
        title="Network Scanner & Finding Explanation Engine"
        subtitle="Non-intrusive port discovery, automated finding explanations, and executive ReportLab PDF generation"
        icon={<Radar size={18} />}
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            {/* Beginner Mode Toggle */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '5px 10px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                fontSize: 12,
              }}
            >
              <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Beginner Explanation:</span>
              <button
                type="button"
                onClick={() => setBeginnerMode(!beginnerMode)}
                style={{
                  padding: '2px 8px',
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 700,
                  fontFamily: 'JetBrains Mono',
                  cursor: 'pointer',
                  border: 'none',
                  background: beginnerMode ? 'var(--accent)' : 'var(--bg-card)',
                  color: beginnerMode ? '#000' : 'var(--text-muted)',
                  transition: 'all 0.15s ease',
                }}
              >
                {beginnerMode ? 'ON (Simple)' : 'OFF (Technical)'}
              </button>
            </div>

            {/* Scan History Select */}
            {scansList.length > 0 && (
              <select
                className="soc-select"
                style={{ fontSize: 11.5, padding: '4px 8px', width: 'auto', maxWidth: 170, fontFamily: 'JetBrains Mono' }}
                value={selectedScanId}
                onChange={(e) => {
                  setSelectedScanId(e.target.value);
                  fetchScanData(e.target.value);
                }}
              >
                {scansList.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.scan_id} ({s.target})
                  </option>
                ))}
              </select>
            )}

            {/* Call Results */}
            {selectedScanId && (
              <button
                className="btn-ghost"
                onClick={handleCallResults}
                disabled={isScanning}
                title="Fetch latest stored scan results from backend"
                style={{ fontSize: 12 }}
              >
                <RefreshCw size={13} className={isScanning ? 'animate-spin' : ''} />
                Call Results
              </button>
            )}

            {/* Preview Report */}
            {activeResults && (
              <button
                className="btn-ghost"
                onClick={handlePreviewReport}
                style={{ fontSize: 12 }}
              >
                <FileText size={13} />
                Preview Report
              </button>
            )}

            {/* Download PDF Button */}
            {activeResults && (
              <button
                className="btn-primary"
                onClick={handleDownloadPDF}
                disabled={pdfState === 'generating'}
                style={{ fontSize: 12, minWidth: 125 }}
              >
                {pdfState === 'generating' ? (
                  <>
                    <LoadingSpinner size={13} />
                    Generating PDF...
                  </>
                ) : pdfState === 'success' ? (
                  <>
                    <CheckCircle2 size={13} />
                    Downloaded
                  </>
                ) : pdfState === 'error' ? (
                  <>
                    <AlertTriangle size={13} />
                    Retry PDF
                  </>
                ) : (
                  <>
                    <Download size={13} />
                    Download PDF
                  </>
                )}
              </button>
            )}
          </div>
        }
      />

      {/* Target Scanner Input Bar */}
      <Card>
        <form onSubmit={handleStartScan} style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 220 }}>
            <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'JetBrains Mono', display: 'block', marginBottom: 4 }}>
              Target IP / Hostname / Subnet (CIDR)
            </label>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <Radar size={15} style={{ position: 'absolute', left: 10, color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="soc-input"
                style={{ paddingLeft: 32, fontFamily: 'JetBrains Mono' }}
                placeholder="e.g. 127.0.0.1, localhost, or 192.168.1.0/24"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required
              />
            </div>
          </div>

          <div style={{ width: 140 }}>
            <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'JetBrains Mono', display: 'block', marginBottom: 4 }}>
              Scan Profile
            </label>
            <select
              className="soc-select"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
            >
              <option value="standard">Standard (26 Ports)</option>
              <option value="fast">Fast (Top 11 Ports)</option>
            </select>
          </div>

          <div style={{ alignSelf: 'flex-end' }}>
            <button
              type="submit"
              disabled={isScanning}
              className="btn-primary"
              style={{ padding: '8px 20px', height: 35 }}
            >
              {isScanning ? (
                <>
                  <LoadingSpinner size={14} />
                  Scanning...
                </>
              ) : (
                <>
                  <Radar size={14} />
                  Scan Network
                </>
              )}
            </button>
          </div>

          {/* Quick Scan Preset Chips */}
          <div style={{ width: '100%', display: 'flex', gap: 8, alignItems: 'center', marginTop: 4, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>Quick Targets:</span>
            {['127.0.0.1', 'localhost', '192.168.1.1', '10.0.0.1'].map((preset) => (
              <button
                key={preset}
                type="button"
                className="btn-ghost"
                style={{ padding: '2px 8px', fontSize: 11, fontFamily: 'JetBrains Mono' }}
                onClick={() => setTarget(preset)}
              >
                {preset}
              </button>
            ))}
          </div>
        </form>

        {pdfMessage && (
          <div
            style={{
              marginTop: 10,
              padding: '6px 12px',
              borderRadius: 4,
              fontSize: 11.5,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: pdfState === 'error' ? 'rgba(225, 29, 72, 0.15)' : 'rgba(16, 185, 129, 0.15)',
              color: pdfState === 'error' ? 'var(--danger)' : 'var(--success)',
            }}
          >
            {pdfState === 'error' ? <AlertTriangle size={13} /> : <CheckCircle2 size={13} />}
            <span>{pdfMessage}</span>
          </div>
        )}
      </Card>

      {/* Main Results View */}
      {isScanning ? (
        <Card>
          <div style={{ textAlign: 'center', padding: '56px 16px' }}>
            <LoadingSpinner size={40} />
            <div style={{ marginTop: 16, fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
              Executing Non-Intrusive Network Scan...
            </div>
            <div style={{ marginTop: 6, fontSize: 12, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
              Target: {target} · Probing TCP Socket Endpoints & Analyzing Service Posture
            </div>
          </div>
        </Card>
      ) : activeResults ? (
        <>
          {/* Executive Network Security Summary */}
          <Card>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <ShieldCheck size={16} color="var(--accent)" />
              <h3 style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)' }}>
                Network Security Summary & What This Means
              </h3>
            </div>

            {/* Scan Execution & Timestamps Banner */}
            {selectedScan && (
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
                  gap: 10,
                  padding: '12px 14px',
                  background: 'rgba(6, 182, 212, 0.05)',
                  border: '1px solid rgba(6, 182, 212, 0.25)',
                  borderRadius: 6,
                  marginBottom: 14,
                  fontSize: 12,
                }}
              >
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', marginBottom: 2 }}>
                    Scan Started
                  </div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600 }}>
                    {formatLocalDateTime(selectedScan.scan_started_at || selectedScan.started_at)}
                  </div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', marginBottom: 2 }}>
                    Scan Completed
                  </div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--text-primary)', fontWeight: 600 }}>
                    {formatLocalDateTime(selectedScan.scan_completed_at || selectedScan.completed_at)}
                  </div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', marginBottom: 2 }}>
                    Scan Duration
                  </div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: '#10b981', fontWeight: 700 }}>
                    {formatDuration(selectedScan.scan_duration ?? selectedScan.duration_seconds)}
                  </div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', marginBottom: 2 }}>
                    Timezone Reference
                  </div>
                  <div style={{ fontFamily: 'JetBrains Mono', color: 'var(--accent)', fontWeight: 600 }}>
                    {selectedScan.timezone || getLocalTimezoneName()} (Stored in UTC)
                  </div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', marginBottom: 2 }}>
                    Status & Severity
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: 'rgba(16, 185, 129, 0.15)',
                        color: 'var(--success)',
                        fontWeight: 700,
                        fontSize: 11,
                      }}
                    >
                      <CheckCircle2 size={12} />
                      {selectedScan.status?.toUpperCase() || 'COMPLETED'}
                    </span>
                    {selectedScan.highest_severity && (
                      <SeverityBadge severity={selectedScan.highest_severity.toLowerCase() as any} />
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* KPI Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10, marginBottom: 14 }}>
              <KPICard
                label="Target Network"
                value={activeResults.target}
                icon={<Globe size={16} />}
                color="#06b6d4"
                subtitle="Scanned scope"
              />
              <KPICard
                label="Hosts Discovered"
                value={activeResults.hosts_discovered}
                icon={<Server size={16} />}
                color="#10b981"
                subtitle="Active endpoints"
              />
              <KPICard
                label="Open Ports"
                value={activeResults.open_ports_count}
                icon={<Layers size={16} />}
                color="#3b82f6"
                subtitle="Listening services"
              />
              <KPICard
                label="Services Identified"
                value={activeResults.services_count}
                icon={<Terminal size={16} />}
                color="#f59e0b"
                subtitle="Distinct protocols"
              />
              <KPICard
                label="Potential Findings"
                value={activeResults.potential_findings_count}
                icon={<AlertTriangle size={16} />}
                color="#f43f5e"
                subtitle="Review points"
              />
            </div>

            {/* Explanation box */}
            <div
              style={{
                padding: '12px 14px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                fontSize: 12.5,
                lineHeight: 1.6,
                color: 'var(--text-secondary)',
              }}
            >
              <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Info size={14} color="var(--accent)" />
                What this means:
              </div>
              <p>{activeResults.summary_text}</p>
              <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-dim)', fontStyle: 'italic' }}>
                Note: An open port alone does not prove a vulnerability or compromise. Classifications highlight potential exposure scope for defensive hardening.
              </div>
            </div>
          </Card>

          {/* Navigation Tabs between Findings, Timeline, and History */}
          <div style={{ display: 'flex', gap: 8, borderBottom: '1px solid var(--border)', paddingBottom: 8 }}>
            <button
              type="button"
              className={scanTab === 'findings' ? 'btn-primary' : 'btn-ghost'}
              onClick={() => setScanTab('findings')}
              style={{ fontSize: 12, padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 6 }}
            >
              <Layers size={13} />
              Discovered Ports & Services ({activeResults.open_ports_count})
            </button>
            <button
              type="button"
              className={scanTab === 'timeline' ? 'btn-primary' : 'btn-ghost'}
              onClick={() => setScanTab('timeline')}
              style={{ fontSize: 12, padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 6 }}
            >
              <Clock size={13} />
              Scan Event Timeline ({scanTimeline.length})
            </button>
            <button
              type="button"
              className={scanTab === 'history' ? 'btn-primary' : 'btn-ghost'}
              onClick={() => setScanTab('history')}
              style={{ fontSize: 12, padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 6 }}
            >
              <History size={13} />
              Scan History ({scansList.length})
            </button>
          </div>

          {/* TAB 1: FINDINGS & SERVICES */}
          {scanTab === 'findings' && (
            <>
              {/* Finding Categories Tabs & Filter Bar */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {categories.map((c) => (
                    <button
                      key={c.key}
                      onClick={() => setActiveCategory(c.key)}
                      style={{
                        padding: '5px 12px',
                        borderRadius: 6,
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: 'pointer',
                        border: '1px solid',
                        borderColor: activeCategory === c.key ? 'var(--accent)' : 'var(--border)',
                        background: activeCategory === c.key ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
                        color: activeCategory === c.key ? 'var(--accent)' : 'var(--text-muted)',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      {c.label}
                    </button>
                  ))}
                </div>

                <div style={{ position: 'relative', width: 220 }}>
                  <Search size={14} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    className="soc-input"
                    style={{ paddingLeft: 28, fontSize: 12 }}
                    placeholder="Filter findings by host, port..."
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                  />
                </div>
              </div>

              {/* Compact Scan Results Table */}
              <Card style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ overflowX: 'auto' }}>
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>IP Address</th>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>State</th>
                        <th>Risk</th>
                        <th style={{ minWidth: 260 }}>Explanation ({beginnerMode ? 'Beginner' : 'Technical'})</th>
                        <th style={{ textAlign: 'right' }}>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPorts.length === 0 ? (
                        <tr>
                          <td colSpan={10} style={{ textAlign: 'center', padding: '36px 16px', color: 'var(--text-muted)' }}>
                            No open ports or findings match the selected category filter.
                          </td>
                        </tr>
                      ) : (
                        filteredPorts.map((p, idx) => {
                          const expl = p.explanation;
                          const explanationText = beginnerMode
                            ? expl.what_is_it_beginner
                            : expl.what_is_it_technical;

                          return (
                            <tr key={`${p.host}-${p.port}-${idx}`}>
                              <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                                {p.hostname || p.host}
                              </td>
                              <td style={{ fontFamily: 'JetBrains Mono', color: 'var(--accent)' }}>
                                {p.host}
                              </td>
                              <td style={{ fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
                                {p.port}
                              </td>
                              <td>
                                <ProtoChip protocol={p.protocol} />
                              </td>
                              <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                                {p.service}
                              </td>
                              <td style={{ color: 'var(--text-muted)', fontSize: 11.5, fontFamily: 'JetBrains Mono' }}>
                                {p.version && p.version !== 'N/A' ? p.version : '—'}
                              </td>
                              <td>
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--success)', fontSize: 11, fontWeight: 700 }}>
                                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--success)' }} />
                                  OPEN
                                </span>
                              </td>
                              <td>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                                  <SeverityBadge severity={p.risk.toLowerCase() as any} />
                                  <button
                                    type="button"
                                    onClick={() => setWhyFinding({
                                      title: `${p.service} on Port ${p.port}`,
                                      reasoning: expl.risk_reasoning,
                                      risk: p.risk
                                    })}
                                    style={{
                                      padding: '1px 5px',
                                      fontSize: 10,
                                      borderRadius: 4,
                                      background: 'rgba(255,255,255,0.06)',
                                      border: '1px solid var(--border)',
                                      color: 'var(--text-muted)',
                                      cursor: 'pointer',
                                      fontFamily: 'JetBrains Mono',
                                    }}
                                    title="Why was this finding classified with this risk level?"
                                  >
                                    Why?
                                  </button>
                                </div>
                              </td>
                              <td style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                                {explanationText}
                              </td>
                              <td style={{ textAlign: 'right' }}>
                                <button
                                  className="btn-ghost"
                                  style={{ padding: '4px 10px', fontSize: 11 }}
                                  onClick={() => setSelectedPort(p)}
                                >
                                  <Eye size={12} /> View Details
                                </button>
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </Card>

              {/* Defensive Recommendations Section */}
              {activeResults.recommendations && activeResults.recommendations.length > 0 && (
                <Card>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                    <Lock size={16} color="var(--accent)" />
                    <h3 style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-primary)' }}>
                      Defensive Security Recommendations
                    </h3>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 10 }}>
                    {activeResults.recommendations.map((rec, i) => (
                      <div
                        key={i}
                        style={{
                          padding: '10px 12px',
                          background: 'var(--bg-secondary)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 6,
                          fontSize: 12,
                          color: 'var(--text-secondary)',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: 8,
                        }}
                      >
                        <CheckCircle2 size={15} color="var(--success)" style={{ flexShrink: 0, marginTop: 2 }} />
                        <span style={{ lineHeight: 1.4 }}>{rec}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </>
          )}

          {/* TAB 2: SCAN EVENT TIMELINE */}
          {scanTab === 'timeline' && (
            <Card style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Clock size={15} color="var(--accent)" />
                  <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-primary)' }}>
                    Chronological Scan Execution Events
                  </span>
                </div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                  Target: {activeResults.target}
                </span>
              </div>
              {loadingTimeline ? (
                <div style={{ textAlign: 'center', padding: 40 }}>
                  <LoadingSpinner size={24} />
                  <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>Loading scan timeline...</div>
                </div>
              ) : scanTimeline.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 36, color: 'var(--text-muted)' }}>
                  No timeline events recorded for this scan.
                </div>
              ) : (
                <div style={{ padding: 16 }}>
                  <div style={{ position: 'relative', paddingLeft: 24 }}>
                    <div style={{ position: 'absolute', left: 8, top: 4, bottom: 4, width: 2, background: 'var(--border)' }} />
                    {scanTimeline.map((ev, i) => (
                      <div key={ev.event_id || i} style={{ position: 'relative', marginBottom: 16, display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                        <div
                          style={{
                            position: 'absolute',
                            left: -20,
                            top: 4,
                            width: 10,
                            height: 10,
                            borderRadius: '50%',
                            background: String(ev.severity || '').toLowerCase() === 'high' || String(ev.severity || '').toLowerCase() === 'critical' ? 'var(--danger)' : String(ev.severity || '').toLowerCase() === 'medium' ? 'var(--warning)' : 'var(--accent)',
                            border: '2px solid var(--bg-card)',
                          }}
                        />
                        <div
                          style={{
                            flex: 1,
                            padding: '10px 14px',
                            background: 'var(--bg-secondary)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 6,
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4, flexWrap: 'wrap', gap: 6 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <span
                                style={{
                                  fontSize: 10.5,
                                  fontFamily: 'JetBrains Mono',
                                  fontWeight: 700,
                                  padding: '2px 6px',
                                  borderRadius: 4,
                                  background: 'rgba(255,255,255,0.06)',
                                  color: 'var(--text-primary)',
                                }}
                              >
                                {ev.event_type}
                              </span>
                              {ev.severity && <SeverityBadge severity={String(ev.severity).toLowerCase() as any} />}
                              {ev.source_ip && (
                                <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--text-muted)' }}>
                                  {ev.source_ip}{ev.destination_port ? `:${ev.destination_port}` : ''}
                                </span>
                              )}
                            </div>
                            <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: 'var(--text-muted)' }}>
                              {formatLocalDateTime(ev.timestamp)}
                            </span>
                          </div>
                          <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                            {ev.description}
                          </div>
                          {ev.evidence && (
                            <div
                              style={{
                                marginTop: 6,
                                fontSize: 11,
                                fontFamily: 'JetBrains Mono',
                                color: 'var(--accent)',
                                background: 'rgba(6, 182, 212, 0.08)',
                                padding: '4px 8px',
                                borderRadius: 4,
                              }}
                            >
                              Evidence: {typeof ev.evidence === 'object' ? JSON.stringify(ev.evidence) : String(ev.evidence)}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          )}

          {/* TAB 3: SCAN HISTORY TABLE */}
          {scanTab === 'history' && (
            <Card style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <History size={15} color="var(--accent)" />
                  <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-primary)' }}>
                    Network Scan Execution History
                  </span>
                </div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Total Scans: {scansList.length}
                </span>
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Scan ID</th>
                      <th>Type</th>
                      <th>Target / Network</th>
                      <th>Started</th>
                      <th>Completed</th>
                      <th>Duration</th>
                      <th style={{ textAlign: 'center' }}>Hosts</th>
                      <th style={{ textAlign: 'center' }}>Ports</th>
                      <th style={{ textAlign: 'center' }}>Findings</th>
                      <th>Highest Severity</th>
                      <th>Status</th>
                      <th style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scansList.length === 0 ? (
                      <tr>
                        <td colSpan={12} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                          No scan history available. Run a new scan above.
                        </td>
                      </tr>
                    ) : (
                      scansList.map((s) => {
                        const isSelected = s.scan_id === selectedScanId;
                        return (
                          <tr
                            key={s.scan_id}
                            style={{
                              background: isSelected ? 'rgba(6, 182, 212, 0.08)' : undefined,
                              cursor: 'pointer',
                            }}
                            onClick={() => {
                              setSelectedScanId(s.scan_id);
                              fetchScanData(s.scan_id);
                            }}
                          >
                            <td style={{ fontFamily: 'JetBrains Mono', fontWeight: 700, color: 'var(--accent)' }}>
                              #{s.scan_id.slice(-6)}
                            </td>
                            <td style={{ textTransform: 'capitalize', fontSize: 11.5 }}>
                              {s.scan_type || 'standard'}
                            </td>
                            <td style={{ fontFamily: 'JetBrains Mono', fontWeight: 600, color: 'var(--text-primary)' }}>
                              {s.target}
                            </td>
                            <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                              {formatLocalDateTime(s.scan_started_at || s.started_at)}
                            </td>
                            <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                              {formatLocalDateTime(s.scan_completed_at || s.completed_at)}
                            </td>
                            <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#10b981', fontWeight: 600 }}>
                              {formatDuration(s.scan_duration ?? s.duration_seconds)}
                            </td>
                            <td style={{ textAlign: 'center', fontFamily: 'JetBrains Mono' }}>
                              {s.hosts_count ?? s.results?.hosts_discovered ?? 1}
                            </td>
                            <td style={{ textAlign: 'center', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                              {s.ports_count ?? s.results?.open_ports_count ?? 0}
                            </td>
                            <td style={{ textAlign: 'center', fontFamily: 'JetBrains Mono', color: '#f43f5e', fontWeight: 600 }}>
                              {s.findings_count ?? s.results?.potential_findings_count ?? 0}
                            </td>
                            <td>
                              <SeverityBadge severity={(s.highest_severity || 'info').toLowerCase() as any} />
                            </td>
                            <td>
                              <span
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 3,
                                  padding: '2px 6px',
                                  borderRadius: 4,
                                  fontSize: 10.5,
                                  fontWeight: 700,
                                  background: 'rgba(16, 185, 129, 0.12)',
                                  color: 'var(--success)',
                                }}
                              >
                                {s.status?.toUpperCase() || 'COMPLETED'}
                              </span>
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <button
                                className="btn-ghost"
                                style={{ padding: '3px 8px', fontSize: 11 }}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedScanId(s.scan_id);
                                  fetchScanData(s.scan_id);
                                  setScanTab('findings');
                                }}
                              >
                                Open Scan
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </>
      ) : (
        <div className="space-y-4">
          <Card>
            <EmptyState
              icon={<Radar size={44} />}
              title="Ready for Network Service Discovery"
              message="Enter a target IP or subnet above and click 'Scan Network' to discover active ports, evaluate exposure posture, and review finding explanations."
            />
          </Card>

          {/* If there are existing scans in history, show them so user can open a previous scan */}
          {scansList.length > 0 && (
            <Card style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <History size={15} color="var(--accent)" />
                  <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-primary)' }}>
                    Previous Scan History
                  </span>
                </div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Total Scans: {scansList.length}
                </span>
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Scan ID</th>
                      <th>Type</th>
                      <th>Target / Network</th>
                      <th>Started</th>
                      <th>Completed</th>
                      <th>Duration</th>
                      <th style={{ textAlign: 'center' }}>Hosts</th>
                      <th style={{ textAlign: 'center' }}>Ports</th>
                      <th style={{ textAlign: 'center' }}>Findings</th>
                      <th>Highest Severity</th>
                      <th>Status</th>
                      <th style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scansList.map((s) => (
                      <tr
                        key={s.scan_id}
                        style={{ cursor: 'pointer' }}
                        onClick={() => {
                          setSelectedScanId(s.scan_id);
                          fetchScanData(s.scan_id);
                          setScanTab('findings');
                        }}
                      >
                        <td style={{ fontFamily: 'JetBrains Mono', fontWeight: 700, color: 'var(--accent)' }}>
                          #{s.scan_id.slice(-6)}
                        </td>
                        <td style={{ textTransform: 'capitalize', fontSize: 11.5 }}>
                          {s.scan_type || 'standard'}
                        </td>
                        <td style={{ fontFamily: 'JetBrains Mono', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {s.target}
                        </td>
                        <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                          {formatLocalDateTime(s.scan_started_at || s.started_at)}
                        </td>
                        <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: 'var(--text-muted)' }}>
                          {formatLocalDateTime(s.scan_completed_at || s.completed_at)}
                        </td>
                        <td style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#10b981', fontWeight: 600 }}>
                          {formatDuration(s.scan_duration ?? s.duration_seconds)}
                        </td>
                        <td style={{ textAlign: 'center', fontFamily: 'JetBrains Mono' }}>
                          {s.hosts_count ?? s.results?.hosts_discovered ?? 1}
                        </td>
                        <td style={{ textAlign: 'center', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                          {s.ports_count ?? s.results?.open_ports_count ?? 0}
                        </td>
                        <td style={{ textAlign: 'center', fontFamily: 'JetBrains Mono', color: '#f43f5e', fontWeight: 600 }}>
                          {s.findings_count ?? s.results?.potential_findings_count ?? 0}
                        </td>
                        <td>
                          <SeverityBadge severity={(s.highest_severity || 'info').toLowerCase() as any} />
                        </td>
                        <td>
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 3,
                              padding: '2px 6px',
                              borderRadius: 4,
                              fontSize: 10.5,
                              fontWeight: 700,
                              background: 'rgba(16, 185, 129, 0.12)',
                              color: 'var(--success)',
                            }}
                          >
                            {s.status?.toUpperCase() || 'COMPLETED'}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="btn-ghost"
                            style={{ padding: '3px 8px', fontSize: 11 }}
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedScanId(s.scan_id);
                              fetchScanData(s.scan_id);
                              setScanTab('findings');
                            }}
                          >
                            Open Scan
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </div>
      )}

      {/* Right-Side Investigation Details Drawer */}
      <Drawer
        isOpen={!!selectedPort}
        onClose={() => setSelectedPort(null)}
        title={selectedPort ? `Finding Details: ${selectedPort.service} (Port ${selectedPort.port})` : 'Finding Details'}
        width={560}
      >
        {selectedPort && (
          <div className="space-y-4" style={{ padding: '8px 0' }}>
            {/* Header info */}
            <div style={{ padding: 12, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div style={{ fontSize: 16, fontWeight: 800, color: 'var(--text-primary)' }}>
                  {selectedPort.service}
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <SeverityBadge severity={selectedPort.risk.toLowerCase() as any} />
                  <ProtoChip protocol={selectedPort.protocol} />
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, fontSize: 11.5, fontFamily: 'JetBrains Mono' }}>
                <div><span style={{ color: 'var(--text-muted)' }}>Host:</span> {selectedPort.host}</div>
                <div><span style={{ color: 'var(--text-muted)' }}>Port:</span> {selectedPort.port}</div>
                <div><span style={{ color: 'var(--text-muted)' }}>Category:</span> {selectedPort.category}</div>
                <div><span style={{ color: 'var(--text-muted)' }}>Version:</span> {selectedPort.version || 'N/A'}</div>
              </div>
            </div>

            {/* Explanation Breakdown */}
            <div className="space-y-3">
              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  What is it?
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {beginnerMode ? selectedPort.explanation.what_is_it_beginner : selectedPort.explanation.what_is_it_technical}
                </div>
              </div>

              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  What was observed?
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedPort.explanation.what_was_observed}
                </div>
              </div>

              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  Why does it matter?
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedPort.explanation.why_it_matters}
                </div>
              </div>

              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  Risk Classification Reasoning
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedPort.explanation.risk_reasoning}
                </div>
              </div>

              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--success)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  Recommended Defensive Actions
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedPort.explanation.recommended_action}
                </div>
              </div>

              <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>
                  Further Investigation Steps
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, whiteSpace: 'pre-line' }}>
                  {selectedPort.explanation.investigation_steps}
                </div>
              </div>
            </div>

            {/* Learn More Button */}
            <div style={{ paddingTop: 6 }}>
              <button
                className="btn-ghost"
                style={{ width: '100%', justifyContent: 'center', fontSize: 12 }}
                onClick={() => setLearnMoreItem({
                  title: selectedPort.service,
                  learn_more: selectedPort.explanation.learn_more
                })}
              >
                <BookOpen size={14} /> Learn More About {selectedPort.service} Protocol
              </button>
            </div>
          </div>
        )}
      </Drawer>

      {/* "Why?" Classification Modal */}
      {whyFinding && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
          onClick={() => setWhyFinding(null)}
        >
          <div
            className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-center mb-4 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <HelpCircle size={16} className="text-cyan-400" />
                <h3 className="text-sm font-bold text-white font-mono">
                  Why {whyFinding.risk}? — {whyFinding.title}
                </h3>
              </div>
              <button
                onClick={() => setWhyFinding(null)}
                className="text-slate-400 hover:text-white"
              >
                <X size={16} />
              </button>
            </div>

            <div className="text-xs text-slate-300 leading-relaxed space-y-3">
              <p>{whyFinding.reasoning}</p>
              <div className="p-3 rounded bg-slate-950/80 border border-slate-800 text-[11px] text-slate-400">
                <strong className="text-cyan-400">Heuristic Rule:</strong> Risk ratings prioritize administrative exposure and transmission encryption status to guide defensive hardening without asserting unproven exploitation.
              </div>
            </div>

            <div className="mt-5 flex justify-end">
              <button
                className="btn-ghost"
                style={{ fontSize: 12 }}
                onClick={() => setWhyFinding(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* "Learn More" Protocol Educational Modal */}
      {learnMoreItem && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
          onClick={() => setLearnMoreItem(null)}
        >
          <div
            className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-center mb-4 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <BookOpen size={16} className="text-cyan-400" />
                <h3 className="text-sm font-bold text-white font-mono">
                  Protocol Primer: {learnMoreItem.learn_more.protocol || learnMoreItem.title}
                </h3>
              </div>
              <button
                onClick={() => setLearnMoreItem(null)}
                className="text-slate-400 hover:text-white"
              >
                <X size={16} />
              </button>
            </div>

            <div className="text-xs text-slate-300 space-y-3 leading-relaxed">
              <div>
                <span className="text-cyan-400 font-bold block mb-1 uppercase font-mono text-[10px]">Common Purpose:</span>
                <p>{learnMoreItem.learn_more.purpose}</p>
              </div>
              <div>
                <span className="text-cyan-400 font-bold block mb-1 uppercase font-mono text-[10px]">Typical Ports:</span>
                <p className="font-mono text-slate-200">{learnMoreItem.learn_more.typical_port}</p>
              </div>
              <div>
                <span className="text-cyan-400 font-bold block mb-1 uppercase font-mono text-[10px]">Security Considerations:</span>
                <p>{learnMoreItem.learn_more.security_considerations}</p>
              </div>
              <div>
                <span className="text-emerald-400 font-bold block mb-1 uppercase font-mono text-[10px]">Analyst Investigation Checklist:</span>
                <p className="text-slate-300">{learnMoreItem.learn_more.analyst_checklist}</p>
              </div>
            </div>

            <div className="mt-5 flex justify-end">
              <button
                className="btn-primary"
                style={{ fontSize: 12 }}
                onClick={() => setLearnMoreItem(null)}
              >
                Got It
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Report Preview Modal */}
      {showReportPreview && reportPreviewData && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)' }}
          onClick={() => setShowReportPreview(false)}
        >
          <div
            className="w-full max-w-3xl max-h-[85vh] bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-center mb-4 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileText size={16} className="text-cyan-400" />
                <h3 className="text-sm font-bold text-white font-mono">
                  Official Scan Report Preview — {reportPreviewData.scan_id}
                </h3>
              </div>
              <button
                onClick={() => setShowReportPreview(false)}
                className="text-slate-400 hover:text-white"
              >
                <X size={16} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-4 pr-1 text-xs text-slate-300">
              <div className="p-4 rounded bg-slate-950 border border-slate-800">
                <div className="text-base font-bold text-white mb-1">
                  NOVA CYBER SPARK™ — Network Security Scan Report
                </div>
                <div className="text-[11px] text-slate-400 font-mono">
                  Founder & Architect: Pranay Kumar Mallem · Generated: {reportPreviewData.report_generated_at}
                </div>
              </div>

              <div className="p-3 bg-slate-950/60 rounded border border-slate-800/80">
                <strong className="text-white">Executive Findings:</strong> {reportPreviewData.scan_data?.summary_text}
              </div>

              <div>
                <h4 className="text-xs font-bold text-slate-200 mb-2 uppercase font-mono">Discovered Endpoints & Ports</h4>
                <div className="border border-slate-800 rounded overflow-hidden">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Risk</th>
                        <th>Finding Title</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(reportPreviewData.scan_data?.findings || []).map((f: any, idx: number) => (
                        <tr key={idx}>
                          <td className="font-mono">{f.host}</td>
                          <td className="font-mono">{f.port}</td>
                          <td>{f.service}</td>
                          <td><SeverityBadge severity={f.severity.toLowerCase()} /></td>
                          <td>{f.title}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 flex justify-between items-center">
              <span className="text-[11px] text-slate-500 font-mono">
                Dynamic ReportLab PDF Ready for Export
              </span>
              <div className="flex gap-2">
                <button
                  className="btn-ghost"
                  style={{ fontSize: 12 }}
                  onClick={() => setShowReportPreview(false)}
                >
                  Close
                </button>
                <button
                  className="btn-primary"
                  style={{ fontSize: 12 }}
                  onClick={() => {
                    setShowReportPreview(false);
                    handleDownloadPDF();
                  }}
                >
                  <Download size={13} /> Download ReportLab PDF
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default NetworkScanner;
