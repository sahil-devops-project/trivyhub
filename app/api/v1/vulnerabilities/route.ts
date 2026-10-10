import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { authenticate } from "@/lib/api-middleware";
import { serializeVuln, severityRank } from "@/lib/vuln-stats";

const isPostgres = (process.env.DATABASE_URL ?? "").startsWith("postgres");

export async function GET(req: NextRequest) {
  const claims = await authenticate(req);
  if (claims instanceof NextResponse) return claims;

  const url = new URL(req.url);
  const page = Math.max(1, parseInt(url.searchParams.get("page") ?? "1", 10) || 1);
  const limit = Math.min(500, Math.max(1, parseInt(url.searchParams.get("limit") ?? "100", 10) || 100));
  const severity = url.searchParams.get("severity") ?? "";
  const projectName = url.searchParams.get("project") ?? "";
  const q = (url.searchParams.get("q") ?? "").trim();
  const offset = (page - 1) * limit;

  // Get latest scan id per project in this org
  const projects = await prisma.project.findMany({
    where: {
      organizationId: claims.organizationId,
      ...(projectName ? { name: projectName } : {}),
    },
    select: {
      id: true,
      scans: {
        orderBy: { scannedAt: "desc" },
        take: 1,
        select: { id: true },
      },
    },
  });

  const latestScanIds = projects
    .map((p) => p.scans[0]?.id)
    .filter((id): id is number => id !== undefined);

  if (latestScanIds.length === 0) {
    return NextResponse.json({ data: [], total: 0, page, limit, counts: {} });
  }

  // SQLite LIKE is already case-insensitive; Postgres needs mode: "insensitive"
  const contains = (field: string) => ({
    [field]: { contains: q, ...(isPostgres ? { mode: "insensitive" } : {}) },
  });
  const baseWhere = {
    scanId: { in: latestScanIds },
    ...(q ? { OR: [contains("cveId"), contains("packageName"), contains("title")] } : {}),
  };

  // Count per severity (ignoring the severity filter so the UI can show all pill counts)
  const groups = await prisma.vulnerability.groupBy({
    by: ["severity"],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    where: baseWhere as any,
    _count: { _all: true },
  });
  const counts: Record<string, number> = {};
  for (const g of groups) counts[g.severity] = g._count._all;

  // Severity is stored as text, so ORDER BY would sort it alphabetically.
  // Walk severities in rank order and page across them instead.
  const severities = Object.keys(counts)
    .filter((s) => !severity || s === severity)
    .sort((a, b) => severityRank(a) - severityRank(b) || a.localeCompare(b));
  const total = severities.reduce((sum, s) => sum + counts[s], 0);

  const data = [];
  let skip = offset;
  let take = limit;
  for (const s of severities) {
    if (take <= 0) break;
    if (skip >= counts[s]) { skip -= counts[s]; continue; }
    const rows = await prisma.vulnerability.findMany({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      where: { ...baseWhere, severity: s } as any,
      orderBy: [{ cvssScore: { sort: "desc", nulls: "last" } }, { cveId: "asc" }, { id: "asc" }],
      skip,
      take,
    });
    data.push(...rows.map(serializeVuln));
    take -= rows.length;
    skip = 0;
  }

  return NextResponse.json({ data, total, page, limit, counts });
}
