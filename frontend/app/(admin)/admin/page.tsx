"use client";
import { Activity, AlertTriangle, Database, Server, ShieldAlert, Users } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, Skeleton } from "@/components/ui/primitives";
import { PageHeader, StatCard, StatusBadge } from "@/components/shared";
import { useApi } from "@/lib/hooks";

export default function AdminHome() {
  const s = useApi<any>("/admin/stats", undefined, { poll: 20000 }); const h = useApi<any>("/admin/health", undefined, { poll: 20000 });
  if (!s.data) return <Skeleton className="h-96" />;
  const d = s.data;
  return <><PageHeader title="Administration" crumbs={[{ label: "Admin" }, { label: "Overview" }]} description="Platform-wide metrics." />
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4"><StatCard label="Registered users" value={d.users.total} icon={Users} hint={`${d.users.new_30d} new in 30d`} /><StatCard label="Active users (30d)" value={d.users.active_30d} /><StatCard label="Suspended accounts" value={d.users.suspended} tone={d.users.suspended ? "text-warning" : ""} /><StatCard label="Total assessments" value={d.assessments.total} icon={Activity} />
      <StatCard label="Vulnerabilities" value={d.vulnerabilities.total} icon={ShieldAlert} /><StatCard label="Provider API requests" value={d.api_requests_total} icon={Server} /><StatCard label="Failed assessments (7d)" value={d.errors.failed_assessments_7d} icon={AlertTriangle} tone={d.errors.failed_assessments_7d ? "text-danger" : ""} /><StatCard label="Failed jobs (7d)" value={d.errors.failed_jobs_7d} tone={d.errors.failed_jobs_7d ? "text-danger" : ""} /></div>
    <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card><CardHeader><CardTitle>System health</CardTitle></CardHeader><CardContent className="space-y-2 text-sm">{h.data ? <>{[["Database (MongoDB)", h.data.database.ok, Database], ["Redis", h.data.redis.ok, Server], ["Background workers", h.data.workers.ok, Activity]].map(([l, ok, I]: any) => <div key={l} className="flex items-center justify-between"><span className="flex items-center gap-2"><I className="h-4 w-4 text-muted-foreground" />{l}</span><span className={ok ? "text-success" : "text-danger"}>{ok ? "healthy" : "down"}{l.startsWith("Background") && ` (${h.data.workers.count})`}</span></div>)}</> : <Skeleton className="h-20" />}</CardContent></Card>
      <Card><CardHeader><CardTitle>AI provider usage</CardTitle></CardHeader><CardContent className="space-y-1.5 text-sm">{Object.keys(d.provider_usage).length === 0 && <p className="text-muted-foreground">No usage recorded yet.</p>}{Object.entries(d.provider_usage as Record<string, any>).map(([k, v]) => <div key={k} className="flex justify-between"><span>{k}</span><span className="tabular-nums text-muted-foreground">{v.requests} req · {v.tokens} tok · {v.assessments} runs</span></div>)}</CardContent></Card>
      <Card><CardHeader><CardTitle>Assessments by status</CardTitle></CardHeader><CardContent className="flex flex-wrap gap-3">{Object.entries(d.assessments.by_status as Record<string, number>).map(([k, v]) => <span key={k} className="flex items-center gap-1.5"><StatusBadge status={k} />{v}</span>)}</CardContent></Card>
      <Card><CardHeader><CardTitle>Plans</CardTitle></CardHeader><CardContent className="flex flex-wrap gap-4 text-sm">{Object.entries(d.plans as Record<string, number>).map(([k, v]) => <span key={k} className="capitalize">{k}: <b>{v}</b></span>)}</CardContent></Card></div></>;
}
