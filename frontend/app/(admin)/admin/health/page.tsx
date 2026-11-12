"use client";
import { CheckCircle2, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, Skeleton } from "@/components/ui/primitives";
import { PageHeader, StatusBadge } from "@/components/shared";
import { useApi } from "@/lib/hooks";

export default function Health() {
  const d = useApi<any>("/admin/health", undefined, { poll: 10000 });
  if (!d.data) return <Skeleton className="h-64" />;
  const h = d.data; const rows = [["Database connectivity", h.database.ok, h.database.error], ["Redis (cache, rate limits, queue broker)", h.redis.ok, h.redis.error], ["Background workers", h.workers.ok, h.workers.ok ? `${h.workers.count} responding` : h.workers.error ?? "no workers responded"]];
  return <><PageHeader title="System health" crumbs={[{ label: "Admin", href: "/admin" }, { label: "System health" }]} description="Auto-refreshes every 10 seconds." actions={<StatusBadge status={h.status === "ok" ? "completed" : "failed"} />} />
    <div className="grid gap-4 md:grid-cols-3">{rows.map(([l, ok, note]: any) => <Card key={l} className="p-4"><div className="flex items-center gap-2">{ok ? <CheckCircle2 className="h-5 w-5 text-success" /> : <XCircle className="h-5 w-5 text-danger" />}<p className="text-sm font-medium">{l}</p></div><p className="mt-2 text-xs text-muted-foreground">{ok ? "Operational" : "Unavailable"}{note ? ` · ${note}` : ""}</p></Card>)}</div>
    <div className="mt-4 grid gap-4 md:grid-cols-2"><Card><CardHeader><CardTitle>Queue</CardTitle></CardHeader><CardContent className="text-sm">Pending broker messages: <b>{h.redis.queue_depth ?? "n/a"}</b></CardContent></Card>
      <Card><CardHeader><CardTitle>Jobs (last 24h)</CardTitle></CardHeader><CardContent className="flex flex-wrap gap-3">{Object.keys(h.jobs).length === 0 && <span className="text-sm text-muted-foreground">No jobs.</span>}{Object.entries(h.jobs as Record<string, number>).map(([k, v]) => <span key={k} className="flex items-center gap-1.5"><StatusBadge status={k} />{v}</span>)}</CardContent></Card></div></>;
}
