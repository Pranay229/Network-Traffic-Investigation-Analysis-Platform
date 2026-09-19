// TypeScript types matching all API responses & Auth/Security schemas

export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';
export type InvestigationStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type AlertSeverity = 'high' | 'medium' | 'low' | 'informational';
export type AlertStatus = 'new' | 'investigating' | 'resolved';
export type HostRole = 'client' | 'server' | 'gateway' | 'unknown';
export type IOCType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'port' | 'user_agent';

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  is_email_verified: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface AdminUser extends User {
  last_login_ip: string | null;
  failed_login_attempts: number;
  active_sessions_count: number;
}

export interface AuthResponse {
  user: User;
  access_token: string;
  token_type: string;
  expires_in: number;
  csrf_token: string;
}

export interface UserSession {
  id: number;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
  last_used_at: string;
  is_current: boolean;
}

export interface AuditLog {
  id: number;
  user_id: number | null;
  event_type: string;
  ip_address: string | null;
  user_agent: string | null;
  resource_type: string | null;
  resource_id: string | null;
  metadata_json: Record<string, unknown> | null;
  created_at: string;
}

export interface Investigation {
  id: number;
  inv_id: string;
  user_id?: number | null;
  owner_email?: string | null;
  filename: string;
  file_size: number;
  file_hash: string | null;
  status: InvestigationStatus;
  progress: number;
  current_stage: string | null;
  error_message: string | null;
  total_packets: number;
  total_bytes: number;
  unique_hosts: number;
  total_alerts: number;
  capture_start: string | null;
  capture_end: string | null;
  capture_duration: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  investigation_status?: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
  severity?: string;
  related_scan_id?: string | null;
  notes?: AnalystNote[];
}

export interface Packet {
  id: number;
  frame_number: number;
  timestamp: number;
  timestamp_str: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length: number;
  tcp_flags: string | null;
  info: string | null;
}

export interface PacketsResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  packets: Packet[];
}

export interface Host {
  id: number;
  ip_address: string;
  role: HostRole;
  total_packets: number;
  total_bytes: number;
  packets_sent: number;
  packets_received: number;
  bytes_sent: number;
  bytes_received: number;
  unique_dest_ips: number;
  unique_dest_ports: number;
  connection_count: number;
  alert_count: number;
  protocols: string[];
  top_ports: number[];
  first_seen: number | null;
  last_seen: number | null;
}

export interface Conversation {
  id: number;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  total_packets: number;
  total_bytes: number;
  packets_a_to_b: number;
  packets_b_to_a: number;
  start_time: number | null;
  end_time: number | null;
  duration: number;
  syn_count: number;
  rst_count: number;
  fin_count: number;
}

export interface DNSRecord {
  id: number;
  timestamp: number;
  timestamp_str: string;
  src_ip: string | null;
  dst_ip: string | null;
  query_name: string | null;
  query_type: string | null;
  is_response: boolean;
  response_code: string | null;
  response_ips: string[];
  ttl: number | null;
}

export interface HTTPRecord {
  id: number;
  timestamp: number;
  timestamp_str: string;
  src_ip: string | null;
  dst_ip: string | null;
  method: string | null;
  host: string | null;
  uri: string | null;
  user_agent: string | null;
  status_code: number | null;
}

export interface Alert {
  id: number;
  alert_id: string;
  severity: AlertSeverity;
  alert_type: string;
  detection_rule: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  first_seen: number | null;
  first_seen_str: string | null;
  last_seen: number | null;
  evidence: Record<string, unknown>;
  reason: string | null;
  recommendations: string | null;
  status: AlertStatus;
  created_at: string;
}

export interface IOC {
  id: number;
  type: IOCType;
  value: string;
  first_seen: string | null;
  last_seen: string | null;
  source_ip: string | null;
  context: string | null;
  occurrences: number;
}

export interface TimelineEvent {
  type: 'packet' | 'alert';
  timestamp: number | null;
  timestamp_str: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  protocol: string | null;
  src_port: number | null;
  dst_port: number | null;
  description: string;
  severity: AlertSeverity | null;
}

export interface OverviewData {
  investigation: Investigation;
  kpi: {
    total_packets: number;
    total_bytes: number;
    unique_hosts: number;
    total_alerts: number;
    capture_duration: number;
    dns_queries: number;
    http_requests: number;
    tcp_packets: number;
    udp_packets: number;
    icmp_packets: number;
  };
  protocol_distribution: Array<{ protocol: string; count: number }>;
  traffic_timeline: Array<{ timestamp: number; packets: number }>;
  alert_severities: Record<AlertSeverity, number>;
  packets_per_second: number;
}

export interface Settings {
  port_scan_min_ports: number;
  port_scan_time_window: number;
  dns_query_threshold: number;
  icmp_threshold: number;
  tcp_conn_threshold: number;
  high_conn_threshold: number;
  long_dns_query_len: number;
  high_subdomain_count: number;
  tshark_path: string;
  tshark_available: boolean;
  max_upload_size_mb: number;
}

export interface SecuritySettings {
  access_token_expire_minutes: number;
  refresh_token_expire_days: number;
  max_login_attempts: number;
  lockout_duration_minutes: number;
  max_pcap_size_mb: number;
  cookie_secure: boolean;
  cookie_samesite: string;
  frontend_url: string;
}

export interface ICMPRecord {
  id: number;
  timestamp: number;
  timestamp_str: string;
  src_ip: string | null;
  dst_ip: string | null;
  icmp_type: number | null;
  icmp_code: number | null;
  icmp_type_name: string | null;
  length: number;
}

export interface ICMPResponse {
  summary: {
    total_icmp_packets: number;
    echo_requests: number;
    echo_replies: number;
    unreachable: number;
    ttl_exceeded: number;
    other_icmp: number;
    suspicious_volume: boolean;
  };
  records: ICMPRecord[];
}

export type ScanRiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface FindingExplanation {
  service: string;
  port: number;
  protocol: string;
  category: string;
  risk: ScanRiskLevel;
  state: string;
  version: string;
  what_is_it_beginner: string;
  what_is_it_technical: string;
  what_was_observed: string;
  why_it_matters: string;
  risk_reasoning: string;
  recommended_action: string;
  investigation_steps: string;
  learn_more: {
    protocol: string;
    purpose: string;
    typical_port: string;
    security_considerations: string;
    analyst_checklist: string;
  };
}

export interface ScanPortItem {
  host: string;
  hostname?: string;
  port: number;
  protocol: string;
  service: string;
  version: string;
  state: string;
  risk: ScanRiskLevel;
  category: string;
  finding_id: string;
  explanation: FindingExplanation;
}

export interface ScanFinding {
  finding_id: string;
  host: string;
  hostname?: string;
  port: number;
  protocol: string;
  service: string;
  severity: ScanRiskLevel;
  category: string;
  state: string;
  version: string;
  banner?: string;
  title: string;
  description: string;
  risk_reasoning: string;
  why_it_matters: string;
  what_is_it_beginner: string;
  what_is_it_technical: string;
  recommended_action: string;
  investigation_steps: string;
  learn_more: {
    protocol: string;
    purpose: string;
    typical_port: string;
    security_considerations: string;
    analyst_checklist: string;
  };
}

export interface ScanHostItem {
  ip: string;
  hostname: string;
  status: string;
  open_ports: number[];
  open_ports_count: number;
  services: string[];
  findings_count: number;
}

export interface ScanResultsData {
  target: string;
  scan_type: string;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  hosts_discovered: number;
  open_ports_count: number;
  services_count: number;
  potential_findings_count: number;
  hosts: ScanHostItem[];
  ports: ScanPortItem[];
  findings: ScanFinding[];
  risk_summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total_findings: number;
  };
  recommendations: string[];
  summary_text: string;
  methodology: {
    scanner: string;
    scan_type: string;
    target: string;
    ports_examined_count: number;
    ports_examined: number[];
    service_detection_enabled: boolean;
    intrusive_exploitation: boolean;
  };
  limitations: string;
}

export interface ScanRecord {
  id: number;
  scan_id: string;
  target: string;
  scan_type: string;
  status: string;
  scan_status?: string;
  started_at: string;
  completed_at?: string;
  scan_started_at?: string;
  scan_completed_at?: string;
  duration_seconds: number;
  scan_duration?: number;
  timezone?: string;
  hosts_discovered: number;
  open_ports_count: number;
  services_count: number;
  potential_findings_count: number;
  highest_severity?: ScanRiskLevel;
  created_at?: string;
  results?: ScanResultsData;
}

export interface ScanEvent {
  event_id: string;
  scan_id?: string;
  timestamp: number;
  timestamp_str: string;
  event_type: string;
  severity: ScanRiskLevel;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  short_explanation: string;
  description?: string;
  observation?: string;
  analysis?: string;
  recommendation?: string;
  evidence?: Record<string, unknown>;
}

export interface TimelineEvent {
  id?: number | string;
  event_id?: string;
  timestamp: number;
  timestamp_str?: string;
  type?: string;
  event_type?: string;
  severity?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  short_explanation?: string;
  description: string;
  observation?: string;
  analysis?: string;
  recommendation?: string;
  evidence?: Record<string, unknown>;
  packet_count?: number;
  total_bytes?: number;
  duration?: number;
  packets_per_second?: number;
  bytes_per_second?: number;
}

export interface TrafficFlow {
  source_ip: string;
  destination_ip: string;
  source_port?: number | null;
  destination_port?: number | null;
  protocol: string;
  first_observed: number;
  first_observed_str: string;
  last_observed: number;
  last_observed_str: string;
  duration: number;
  packet_count: number;
  total_bytes: number;
  total_bytes_str: string;
  packets_per_second: number;
  bytes_per_second: number;
  average_rate_str: string;
}

export interface TrafficActivityResponse {
  summary: {
    total_flows: number;
    total_bytes: number;
    total_bytes_str: string;
    capture_duration: number;
    packets_per_second: number;
    bytes_per_second: number;
    average_throughput_str: string;
    high_traffic_events_count: number;
    first_observed: number;
    first_observed_str: string;
    last_observed: number;
    last_observed_str: string;
  };
  top_flows: TrafficFlow[];
  thresholds: {
    high_packet_rate: number;
    high_byte_rate: number;
    high_connection_rate: number;
    large_data_transfer: number;
  };
}

export interface AnalystNote {
  id: string;
  user_id: number | null;
  user_email: string | null;
  note: string;
  timestamp: string;
}

export interface ProtocolDistributionItem {
  protocol: string;
  packets: number;
  bytes: number;
  percentage: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface ProtocolAnalysisResponse {
  protocols: ProtocolDistributionItem[];
  total_packets: number;
  total_bytes: number;
  categories: {
    core_network: ProtocolDistributionItem[];
    web_traffic: ProtocolDistributionItem[];
    network_services: ProtocolDistributionItem[];
    remote_access: ProtocolDistributionItem[];
    other: ProtocolDistributionItem[];
  };
  summary: {
    tcp_packets: number;
    udp_packets: number;
    icmp_packets: number;
    arp_packets: number;
    dns_packets: number;
    http_packets: number;
    tls_packets: number;
    ssh_packets: number;
  };
}

export interface TrafficEngineBucket {
  timestamp: number;
  timestamp_str: string;
  packets: number;
  bytes: number;
  connection_attempts: number;
}

export interface TrafficEngineResponse {
  window: string;
  summary: {
    total_packets: number;
    total_bytes: number;
    packets_per_sec: number;
    bytes_per_sec: number;
    connection_count: number;
    connection_rate: number;
    avg_packet_size: number;
    first_observed: string | null;
    last_observed: string | null;
    duration: number;
  };
  top_sources: Array<{ ip: string; packets: number; bytes: number }>;
  top_destinations: Array<{ ip: string; packets: number; bytes: number }>;
  top_conversations: Array<{ src: string; dst: string; proto: string; packets: number; bytes: number }>;
  top_protocols: Array<{ protocol: string; packets: number; bytes: number }>;
  top_ports: Array<{ port: number; packets: number }>;
  buckets: TrafficEngineBucket[];
}

export interface SecurityEventRecord {
  event_id: string;
  investigation_id: string;
  scan_id?: string | null;
  timestamp: string;
  event_type: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  protocol?: string | null;
  description: string;
  evidence: Record<string, unknown>;
  first_observed?: string | null;
  last_observed?: string | null;
  created_at: string;
  observation?: string;
  analysis?: string;
  recommendation?: string;
}

export interface ARPRecordItem {
  id: number;
  ip_address: string;
  mac_address: string;
  opcode: string;
  first_seen: string;
  last_seen: string;
  packet_count: number;
  is_inconsistent: boolean;
}

export interface TLSMetadataItem {
  id: number;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  sni: string | null;
  tls_version: string | null;
  cipher_suite: string | null;
  timestamp: string;
}
