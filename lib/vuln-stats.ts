import { prisma } from "@/lib/prisma";

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  total: number;
  fixable: number;
}

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0, fixable: 0 };
}

// Per-scan severity counts, aggregated in the database instead of loading every row.
export async function countsByScan(scanIds: number[]): Promise<Map<number, SeverityCounts>> {
  const result = new Map<number, SeverityCounts>();
  if (scanIds.length === 0) return result;

  const [bySeverity, fixable] = await Promise.all([
    prisma.vulnerability.groupBy({
      by: ["scanId", "severity"],
      where: { scanId: { in: scanIds } },
      _count: { _all: true },
    }),
    prisma.vulnerability.groupBy({
      by: ["scanId"],
      where: { scanId: { in: scanIds }, fixedVersion: { not: "" } },
      _count: { _all: true },
    }),
  ]);

  for (const id of scanIds) result.set(id, emptyCounts());

  for (const row of bySeverity) {
    const c = result.get(row.scanId)!;
    const n = row._count._all;
    c.total += n;
    switch (row.severity) {
      case "CRITICAL": c.critical += n; break;
      case "HIGH":     c.high += n; break;
      case "MEDIUM":   c.medium += n; break;
      case "LOW":      c.low += n; break;
      default:         c.unknown += n;
    }
  }
  for (const row of fixable) result.get(row.scanId)!.fixable = row._count._all;

  return result;
}

interface DbVulnerability {
  id: number;
  scanId: number;
  cveId: string;
  severity: string;
  packageName: string;
  installedVersion: string;
  fixedVersion: string;
  title: string;
  description: string;
  primaryUrl: string;
  isFixed: boolean;
  firstSeenAt: Date;
  cvssScore: number | null;
}

// The UI (lib/types.ts) uses snake_case field names.
export function serializeVuln(v: DbVulnerability) {
  return {
    id: v.id,
    scan_id: v.scanId,
    cve_id: v.cveId,
    severity: v.severity,
    package_name: v.packageName,
    installed_version: v.installedVersion,
    fixed_version: v.fixedVersion,
    title: v.title,
    description: v.description,
    primary_url: v.primaryUrl,
    is_fixed: v.isFixed,
    first_seen_at: v.firstSeenAt,
    cvss_score: v.cvssScore,
  };
}

export function severityRank(s: string) {
  const i = SEVERITY_ORDER.indexOf(s as (typeof SEVERITY_ORDER)[number]);
  return i === -1 ? SEVERITY_ORDER.length : i;
}
