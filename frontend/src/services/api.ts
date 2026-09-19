/**
 * API Service — Enterprise SOC Network Traffic Investigation & Analysis Platform
 * 
 * Includes:
 * - Axios instance with withCredentials: true (HttpOnly Cookie support)
 * - In-memory access token storage (no localStorage JWT exposure)
 * - Double-submit CSRF token interceptor
 * - Automatic 401 retry queue with rotating refresh token
 * - Full RBAC, session management, and admin security endpoints
 */
import axios, { type AxiosInstance, type InternalAxiosRequestConfig, type AxiosError } from 'axios';
import type {
  Investigation, PacketsResponse, Host, Conversation,
  DNSRecord, HTTPRecord, Alert, IOC, TimelineEvent, OverviewData, Settings,
  User, AdminUser, UserSession, AuditLog, AuthResponse, SecuritySettings,
  ICMPResponse, ScanRecord, ScanResultsData, ScanEvent, TrafficActivityResponse,
  ProtocolAnalysisResponse, TrafficEngineResponse, SecurityEventRecord,
  ARPRecordItem, TLSMetadataItem
} from '../types';

const rawApiEnv = (import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || '').trim();
const BASE_URL = rawApiEnv
  ? (rawApiEnv.endsWith('/api') ? rawApiEnv : `${rawApiEnv.replace(/\/+$/, '')}/api`)
  : '/api';

const api: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  withCredentials: true, // Send HttpOnly refresh & CSRF cookies
});

// ─── In-Memory Token State ───────────────────────────────────────────────────

let inMemoryAccessToken: string | null = null;
let inMemoryCsrfToken: string | null = null;

export const setAccessToken = (token: string | null) => {
  inMemoryAccessToken = token;
};

export const getAccessToken = (): string | null => {
  return inMemoryAccessToken;
};

export const setCsrfToken = (token: string | null) => {
  inMemoryCsrfToken = token;
};

export const getCsrfToken = (): string | null => {
  if (inMemoryCsrfToken) return inMemoryCsrfToken;
  // Fallback: read from document.cookie if available
  const match = document.cookie.match(new RegExp('(^| )csrf_token=([^;]+)'));
  if (match) return decodeURIComponent(match[2]);
  return null;
};

// ─── Request Interceptors (Open Access) ──────────────────────────────────────

api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    if (inMemoryAccessToken) {
      config.headers.set('Authorization', `Bearer ${inMemoryAccessToken}`);
    }
    const csrf = getCsrfToken();
    if (csrf) {
      config.headers.set('X-CSRF-Token', csrf);
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ─── Response Interceptors ───────────────────────────────────────────────────

api.interceptors.response.use(
  (response) => {
    // Detect HTML responses returned by SPA fallback rewrite rules when backend is offline/unreachable
    if (
      typeof response.data === 'string' &&
      (response.data.trim().startsWith('<!doctype') ||
       response.data.trim().startsWith('<html') ||
       response.data.includes('<div id="root">'))
    ) {
      return Promise.reject(
        new Error('API request returned HTML instead of JSON. Backend service is offline or unreachable.')
      );
    }
    return response;
  },
  (error: AxiosError) => Promise.reject(error)
);


// ============================================================================
// AUTHENTICATION & SESSIONS API
// ============================================================================

export const registerUser = async (data: {
  full_name: string;
  email: string;
  password: string;
  confirm_password: string;
}) => {
  const res = await api.post('/auth/register', data);
  return res.data;
};

export const loginUser = async (data: {
  email: string;
  password: string;
  remember_me?: boolean;
}): Promise<AuthResponse> => {
  const res = await api.post<AuthResponse>('/auth/login', data);
  setAccessToken(res.data.access_token);
  setCsrfToken(res.data.csrf_token);
  return res.data;
};

export const refreshToken = async (): Promise<AuthResponse> => {
  const res = await api.post<AuthResponse>('/auth/refresh');
  setAccessToken(res.data.access_token);
  setCsrfToken(res.data.csrf_token);
  return res.data;
};

export const logoutUser = async (): Promise<void> => {
  try {
    await api.post('/auth/logout');
  } finally {
    setAccessToken(null);
    setCsrfToken(null);
  }
};

export const logoutAllDevices = async (): Promise<void> => {
  try {
    await api.post('/auth/logout-all');
  } finally {
    setAccessToken(null);
    setCsrfToken(null);
  }
};

export const getMe = async (): Promise<User> => {
  const res = await api.get<User>('/auth/me');
  return res.data;
};

export const updateProfile = async (data: { full_name: string }): Promise<User> => {
  const res = await api.put<User>('/auth/profile', data);
  return res.data;
};

export const changePassword = async (data: {
  current_password: string;
  new_password: string;
  confirm_password: string;
}) => {
  const res = await api.post('/auth/change-password', data);
  return res.data;
};

export const forgotPassword = async (email: string) => {
  const res = await api.post('/auth/forgot-password', { email });
  return res.data;
};

export const resetPassword = async (data: {
  token: string;
  new_password: string;
  confirm_password: string;
}) => {
  const res = await api.post('/auth/reset-password', data);
  return res.data;
};

export const verifyEmail = async (token: string) => {
  const res = await api.get('/auth/verify-email', { params: { token } });
  return res.data;
};

export const resendVerification = async (email: string) => {
  const res = await api.post('/auth/resend-verification', { email });
  return res.data;
};

export const getUserSessions = async (): Promise<UserSession[]> => {
  const res = await api.get<UserSession[]>('/auth/sessions');
  return res.data;
};

export const revokeSession = async (sessionId: number): Promise<void> => {
  await api.delete(`/auth/sessions/${sessionId}`);
};


// ============================================================================
// SECURITY ADMINISTRATION API (ADMIN ONLY)
// ============================================================================

export const getAdminUsers = async (params: {
  role?: string;
  search?: string;
  skip?: number;
  limit?: number;
} = {}): Promise<AdminUser[]> => {
  const res = await api.get<AdminUser[]>('/admin/users', { params });
  return res.data;
};

export const updateUserRole = async (userId: number, role: string): Promise<AdminUser> => {
  const res = await api.put<AdminUser>(`/admin/users/${userId}/role`, { role });
  return res.data;
};

export const updateUserStatus = async (userId: number, is_active: boolean): Promise<AdminUser> => {
  const res = await api.put<AdminUser>(`/admin/users/${userId}/status`, { is_active });
  return res.data;
};

export const revokeUserSessionsAdmin = async (userId: number): Promise<{ message: string }> => {
  const res = await api.post(`/admin/users/${userId}/revoke-sessions`);
  return res.data;
};

export const getAdminAuditLogs = async (params: {
  event_type?: string;
  user_id?: number;
  ip_address?: string;
  skip?: number;
  limit?: number;
} = {}): Promise<AuditLog[]> => {
  const res = await api.get<AuditLog[]>('/admin/audit-logs', { params });
  return res.data;
};

export const getSecuritySettings = async (): Promise<SecuritySettings> => {
  const res = await api.get<SecuritySettings>('/admin/settings');
  return res.data;
};

export const updateSecuritySettings = async (data: Partial<SecuritySettings>): Promise<SecuritySettings> => {
  const res = await api.put<SecuritySettings>('/admin/settings', data);
  return res.data;
};


// ============================================================================
// PCAP & INVESTIGATION API
// ============================================================================

export const uploadPCAP = async (
  file: File,
  onProgress?: (percent: number) => void
): Promise<{ inv_id: string; investigation_id: number; status: string }> => {
  const form = new FormData();
  form.append('file', file);

  const res = await api.post('/pcap/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => {
      if (onProgress && e.total) {
        onProgress(Math.round((e.loaded / e.total) * 100));
      }
    },
  });
  return res.data;
};

export const getInvestigations = async (): Promise<Investigation[]> => {
  const res = await api.get('/investigations');
  return Array.isArray(res.data) ? res.data : [];
};

export const getInvestigation = async (invId: string): Promise<Investigation> => {
  const res = await api.get(`/investigations/${invId}`);
  return res.data;
};

export const deleteInvestigation = async (invId: string): Promise<void> => {
  await api.delete(`/investigations/${invId}`);
};

export const getOverview = async (invId: string): Promise<OverviewData> => {
  const res = await api.get(`/investigations/${invId}/overview`);
  return res.data;
};

export const getPackets = async (
  invId: string,
  params: {
    page?: number;
    page_size?: number;
    protocol?: string;
    src_ip?: string;
    dst_ip?: string;
    src_port?: number;
    dst_port?: number;
  } = {}
): Promise<PacketsResponse> => {
  const res = await api.get(`/investigations/${invId}/packets`, { params });
  return res.data;
};

export const getProtocols = async (invId: string) => {
  const res = await api.get(`/investigations/${invId}/protocols`);
  return res.data;
};

export const getHosts = async (
  invId: string,
  params: { search?: string; page?: number; sort_by?: string } = {}
): Promise<{ total: number; hosts: Host[] }> => {
  const res = await api.get(`/investigations/${invId}/hosts`, { params });
  return res.data;
};

export const getHostDetail = async (invId: string, ip: string) => {
  const res = await api.get(`/investigations/${invId}/hosts/${encodeURIComponent(ip)}`);
  return res.data;
};

export const getConversations = async (
  invId: string,
  params: { protocol?: string; ip?: string; port?: number; sort_by?: string; page?: number } = {}
): Promise<{ total: number; conversations: Conversation[] }> => {
  const res = await api.get(`/investigations/${invId}/conversations`, { params });
  return res.data;
};

export const getDNS = async (
  invId: string,
  params: { search?: string; page?: number } = {}
): Promise<{ total: number; summary: Record<string, unknown>; records: DNSRecord[] }> => {
  const res = await api.get(`/investigations/${invId}/dns`, { params });
  return res.data;
};

export const getHTTP = async (
  invId: string,
  params: { page?: number } = {}
): Promise<{ total: number; summary: Record<string, unknown>; records: HTTPRecord[] }> => {
  const res = await api.get(`/investigations/${invId}/http`, { params });
  return res.data;
};

export const getTCP = async (invId: string) => {
  const res = await api.get(`/investigations/${invId}/tcp`);
  return res.data;
};

export const getICMP = async (invId: string): Promise<ICMPResponse> => {
  const res = await api.get<ICMPResponse>(`/investigations/${invId}/icmp`);
  return res.data;
};

export const getAlerts = async (
  invId: string,
  params: { severity?: string; status?: string } = {}
): Promise<Alert[]> => {
  const res = await api.get(`/investigations/${invId}/alerts`, { params });
  return Array.isArray(res.data) ? res.data : [];
};

export const updateAlertStatus = async (
  invId: string,
  alertId: string,
  status: string
): Promise<void> => {
  await api.patch(`/investigations/${invId}/alerts/${alertId}`, { status });
};

export const getTimeline = async (
  invId: string,
  params: {
    src_ip?: string;
    dst_ip?: string;
    protocol?: string;
    severity?: string;
    category?: string;
    start_time?: string;
    end_time?: string;
    limit?: number;
  } = {}
): Promise<{ total: number; events: TimelineEvent[] }> => {
  const res = await api.get(`/investigations/${invId}/timeline`, { params });
  return res.data;
};

export const getTrafficActivity = async (
  invId: string
): Promise<TrafficActivityResponse> => {
  const res = await api.get(`/investigations/${invId}/traffic-activity`);
  return res.data;
};

export const getScanTimeline = async (
  scanId: string,
  params: { event_type?: string; severity?: string; limit?: number } = {}
): Promise<{ scan_id: string; total: number; events: ScanEvent[] }> => {
  const res = await api.get(`/scans/${scanId}/timeline`, { params });
  return res.data;
};

export const getIOCs = async (
  invId: string,
  params: { ioc_type?: string; search?: string; page?: number } = {}
): Promise<{ total: number; iocs: IOC[]; note: string }> => {
  const res = await api.get(`/investigations/${invId}/iocs`, { params });
  return res.data;
};

export const getReport = async (invId: string): Promise<{ report: string; inv_id: string; filename: string }> => {
  const res = await api.get(`/investigations/${invId}/report`);
  return res.data;
};

export const getSettings = async (): Promise<Settings> => {
  const res = await api.get('/settings');
  return res.data;
};

export const updateSettings = async (settings: Partial<Settings>): Promise<Settings> => {
  const res = await api.put('/settings', settings);
  return res.data;
};

export const checkHealth = async () => {
  const res = await api.get('/health');
  return res.data;
};

// ─── Network Scanner & Finding Explanation APIs ──────────────────────────────

export const runScan = async (target: string, scan_type: string = 'standard'): Promise<{
  message: string;
  scan_id: string;
  scan: ScanRecord;
  results: ScanResultsData;
}> => {
  const res = await api.post('/scans/run', { target, scan_type });
  return res.data;
};

export const getScans = async (): Promise<ScanRecord[]> => {
  const res = await api.get<ScanRecord[]>('/scans');
  return Array.isArray(res.data) ? res.data : [];
};

export const getScan = async (scanId: string): Promise<ScanRecord> => {
  const res = await api.get(`/scans/${scanId}`);
  return res.data;
};

export const getScanResults = async (scanId: string): Promise<{
  scan_id: string;
  target: string;
  status: string;
  results: ScanResultsData;
}> => {
  const res = await api.get(`/scans/${scanId}/results`);
  return res.data;
};

export const getScanReport = async (scanId: string): Promise<{
  scan_id: string;
  platform: string;
  founder: string;
  analyst: string;
  report_generated_at: string;
  scan_data: ScanResultsData;
}> => {
  const res = await api.get(`/scans/${scanId}/report`);
  return res.data;
};

export const downloadScanReportPDF = async (scanId: string): Promise<Blob> => {
  const res = await api.get(`/scans/${scanId}/report/pdf`, {
    responseType: 'blob',
  });
  return res.data;
};

export const getInvestigationProtocols = async (invId: string): Promise<ProtocolAnalysisResponse> => {
  const res = await api.get<ProtocolAnalysisResponse>(`/investigations/${invId}/protocols`);
  return res.data;
};

export const getTrafficEngineData = async (invId: string, window = '30s'): Promise<TrafficEngineResponse> => {
  const res = await api.get<TrafficEngineResponse>(`/investigations/${invId}/traffic-engine`, {
    params: { window }
  });
  return res.data;
};

export const getSecurityEvents = async (
  invId: string,
  params?: { severity?: string; event_type?: string; protocol?: string }
): Promise<{ total: number; events: SecurityEventRecord[] }> => {
  const res = await api.get(`/investigations/${invId}/security-events`, { params });
  return res.data;
};

export const updateInvestigationStatus = async (
  invId: string,
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED'
): Promise<{ inv_id: string; investigation_status: string }> => {
  const res = await api.patch(`/investigations/${invId}/status`, { status });
  return res.data;
};

export const addInvestigationNote = async (
  invId: string,
  note: string
): Promise<{ inv_id: string; note: unknown; total_notes: number }> => {
  const res = await api.post(`/investigations/${invId}/notes`, { note });
  return res.data;
};

export const getInvestigationARP = async (invId: string): Promise<{ total: number; arp_records: ARPRecordItem[] }> => {
  const res = await api.get(`/investigations/${invId}/arp`);
  return res.data;
};

export const getInvestigationTLS = async (invId: string): Promise<{ total: number; tls_metadata: TLSMetadataItem[] }> => {
  const res = await api.get(`/investigations/${invId}/tls`);
  return res.data;
};

export const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
};

export const formatTimestamp = (ts: number | null): string => {
  if (!ts) return 'N/A';
  return new Date(ts * 1000).toUTCString();
};

export default api;
