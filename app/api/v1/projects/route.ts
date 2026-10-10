import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { authenticate } from "@/lib/api-middleware";
import { countsByScan, emptyCounts } from "@/lib/vuln-stats";

const TREND_SCANS = 14;

export async function GET(req: NextRequest) {
  const claims = await authenticate(req);
  if (claims instanceof NextResponse) return claims;

  const projects = await prisma.project.findMany({
    where: { organizationId: claims.organizationId },
    orderBy: { name: "asc" },
    include: {
      scans: {
        orderBy: { scannedAt: "desc" },
        take: TREND_SCANS,
        select: { id: true, scannedAt: true, branch: true, langs: true },
      },
      _count: { select: { scans: true } },
    },
  });

  const counts = await countsByScan(projects.flatMap((p) => p.scans.map((s) => s.id)));

  const summaries = projects.map((p) => {
    const lastScan = p.scans[0] ?? null;
    const prevScan = p.scans[1] ?? null;
    const c = (lastScan && counts.get(lastScan.id)) || emptyCounts();
    const prevTotal = prevScan ? counts.get(prevScan.id)?.total ?? 0 : c.total;
    return {
      id: p.id,
      organization_id: p.organizationId,
      name: p.name,
      environment: p.environment,
      owner: p.owner,
      created_at: p.createdAt,
      last_scan: lastScan?.scannedAt ?? null,
      branch: lastScan?.branch ?? null,
      langs: lastScan ? (JSON.parse(lastScan.langs || "[]") as string[]) : [],
      total_scans: p._count.scans,
      ...c,
      delta: c.total - prevTotal,
      // Oldest → newest totals of the most recent scans
      trend: [...p.scans].reverse().map((s) => counts.get(s.id)?.total ?? 0),
    };
  });

  return NextResponse.json(summaries);
}
