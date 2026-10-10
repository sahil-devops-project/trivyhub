import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { authenticate } from "@/lib/api-middleware";
import { serializeVuln } from "@/lib/vuln-stats";

export async function GET(req: NextRequest) {
  const claims = await authenticate(req);
  if (claims instanceof NextResponse) return claims;

  const name = new URL(req.url).searchParams.get("name");
  if (!name) return NextResponse.json({ error: "name query param required" }, { status: 400 });

  const project = await prisma.project.findFirst({
    where: { organizationId: claims.organizationId, name },
  });
  if (!project) return NextResponse.json({ error: "project not found" }, { status: 404 });

  const scans = await prisma.scan.findMany({
    where: { projectId: project.id },
    orderBy: { scannedAt: "desc" },
    take: 2,
    select: { id: true },
  });

  if (scans.length < 2) {
    return NextResponse.json({ message: "not enough scans to compute diff", scans: scans.length });
  }

  const [current, previous] = await Promise.all([
    prisma.vulnerability.findMany({ where: { scanId: scans[0].id } }),
    prisma.vulnerability.findMany({ where: { scanId: scans[1].id } }),
  ]);

  const currentKeys = new Set(current.map((v) => v.cveId + v.packageName));
  const previousKeys = new Set(previous.map((v) => v.cveId + v.packageName));

  return NextResponse.json({
    new_vulnerabilities: current.filter((v) => !previousKeys.has(v.cveId + v.packageName)).map(serializeVuln),
    resolved_vulnerabilities: previous.filter((v) => !currentKeys.has(v.cveId + v.packageName)).map(serializeVuln),
    previous_scan_id: scans[1].id,
    current_scan_id: scans[0].id,
  });
}
