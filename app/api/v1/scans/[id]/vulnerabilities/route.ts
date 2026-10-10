import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { authenticate } from "@/lib/api-middleware";
import { serializeVuln, severityRank } from "@/lib/vuln-stats";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const claims = await authenticate(req);
  if (claims instanceof NextResponse) return claims;

  const { id } = await params;
  const scanId = parseInt(id, 10);
  if (isNaN(scanId)) return NextResponse.json({ error: "invalid scan id" }, { status: 400 });

  // Only allow access to scans belonging to the caller's organization
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: claims.organizationId } },
    select: { id: true },
  });
  if (!scan) return NextResponse.json({ error: "scan not found" }, { status: 404 });

  const vulns = await prisma.vulnerability.findMany({ where: { scanId } });
  vulns.sort((a, b) =>
    severityRank(a.severity) - severityRank(b.severity) || (b.cvssScore ?? -1) - (a.cvssScore ?? -1)
  );
  return NextResponse.json(vulns.map(serializeVuln));
}
