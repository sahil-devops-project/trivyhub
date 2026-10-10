export type Role = "owner" | "admin" | "member" | "viewer";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface User {
  id: number;
  organization_id: number;
  email: string;
  role: Role;
  created_at: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export interface APIKey {
  id: number;
  organization_id: number;
  name: string;
  key_prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked: boolean;
  key?: string;
}

export interface Project {
  id: number;
  organization_id: number;
  name: string;
  environment: string;
  owner: string;
  created_at: string;
  last_scan: string | null;
  branch: string | null;
  langs: string[];
  total_scans: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  total: number;
  fixable: number;
  /** change in total vulnerabilities vs. the previous scan */
  delta: number;
  /** totals of the most recent scans, oldest → newest */
  trend: number[];
}

export interface Vulnerability {
  id: number;
  scan_id: number;
  cve_id: string;
  severity: Severity;
  package_name: string;
  installed_version: string;
  fixed_version: string;
  title: string;
  description: string;
  primary_url: string;
  is_fixed: boolean;
  first_seen_at: string;
  cvss_score: number | null;
}

export interface ScanSummary {
  id: number;
  project_id: number;
  image_name: string;
  image_digest: string;
  scanned_at: string;
  pipeline_id: string | null;
  pipeline_url: string | null;
  branch: string | null;
  commit: string | null;
  triggered_by: string | null;
  langs: string[] | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  total: number;
  fixable: number;
}

export interface DiffResult {
  current_scan_id: number;
  previous_scan_id: number;
  new_vulnerabilities: Vulnerability[];
  resolved_vulnerabilities: Vulnerability[];
}
