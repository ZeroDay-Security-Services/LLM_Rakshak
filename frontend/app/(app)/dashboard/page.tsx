"use client";
import Link from "next/link";
import { Activity, AlertTriangle, CheckCircle2, Gauge, PlayCircle, ShieldAlert, Plus, ShieldCheck } from "lucide-react";
import { Button, Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/primitives";
import { EmptyState, PageHeader, SeverityBadge, StatCard, StatusBadge, ScoreRing } from "@/components/shared";
import { CategoryBars, HistoryChart, ModelComparison, OutcomeChart, ScoreTrend, SeverityChart } from "@/components/charts";
import { Skeleton } from "@/components/ui/primitives";
import { useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, scoreColor, timeAgo } from "@/lib/utils";

export default function Dashboard() {
  const { data: d, loading, error } = useApi<any>("/dashboard", undefined, { poll: 15000 });
  const { can } = useAuth();
  if (loading && !d) return <div className="space-y-4"><Skeleton className="h-8 w-48" /><div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{[...Array(8)].map((_, i) => <Skeleton key={i} className="h-24" />)}</div><Skeleton className="h-64" /></div>;
  if (error || !d) return <EmptyState icon={AlertTriangle} title="Could not load the dashboard" description={error?.message} />;
  const t = d.totals;
  const New = can("assessment:write") && <Button asChild><Link href="/assessments/new"><Plus className="h-4 w-4" />New assessment</Link></Button>;
  if (d.empty) return <><PageHeader title="Dashboard" description="Your AI security posture at a glance." actions={New} />
    <EmptyState icon={ShieldCheck} title="No assessments yet" description="Connect a model and run your first assessment. Results, scores and trends will appear here, computed from your real data." action={<div className="flex gap-2"><Button variant="outline" asChild><Link href="/settings?tab=api">Add API key</Link></Button><Button asChild><Link href="/models">Add a model</Link></Button></div>} /></>;
  return <><PageHeader title="Dashboard" description="Your AI security posture at a glance." actions={New} />
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatCard label="Total assessments" value={t.assessments} icon={PlayCircle} /><StatCard label="Completed" value={t.completed} icon={CheckCircle2} /><StatCard label="Running" value={t.running} icon={Activity} tone={t.running ? "text-primary" : ""} />
      <StatCard label="Security posture" value={t.posture_score ?? "N/A"} icon={Gauge} tone={scoreColor(t.posture_score)} hint="Latest score per model" />
      <StatCard label="Open vulnerabilities" value={t.vulnerabilities} icon={ShieldAlert} /><StatCard label="Critical" value={t.critical} tone={t.critical ? "text-sev-critical" : ""} /><StatCard label="High" value={t.high} tone={t.high ? "text-sev-high" : ""} />
      <StatCard label="Medium / Low" value={`${t.medium} / ${t.low}`} hint={`${t.info} informational`} /></div>
    <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
      <Card><CardHeader><CardTitle>Severity distribution</CardTitle><CardDescription>Open findings</CardDescription></CardHeader><CardContent><SeverityChart data={d.charts.severity} /></CardContent></Card>
      <Card className="lg:col-span-2"><CardHeader><CardTitle>Assessment history</CardTitle><CardDescription>Last 30 days</CardDescription></CardHeader><CardContent><HistoryChart data={d.charts.assessment_history} /></CardContent></Card>
      <Card className="lg:col-span-2"><CardHeader><CardTitle>Security score trend</CardTitle><CardDescription>Completed assessments</CardDescription></CardHeader><CardContent><ScoreTrend data={d.charts.score_trend} /></CardContent></Card>
      <Card><CardHeader><CardTitle>Outcomes</CardTitle><CardDescription>Success vs failure</CardDescription></CardHeader><CardContent><OutcomeChart data={d.charts.outcomes} /></CardContent></Card>
      <Card><CardHeader><CardTitle>Vulnerability categories</CardTitle></CardHeader><CardContent><CategoryBars data={d.charts.categories} /></CardContent></Card>
      <Card className="lg:col-span-2"><CardHeader><CardTitle>Model-wise comparison</CardTitle><CardDescription>Latest score and open findings per model</CardDescription></CardHeader><CardContent><ModelComparison data={d.charts.model_comparison} /></CardContent></Card></div>
    <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card><CardHeader><CardTitle>Latest assessments</CardTitle></CardHeader><CardContent className="space-y-1">{d.recent.assessments.map((a: any) => <Link key={a.id} href={`/assessments/${a.id}`} className="flex items-center justify-between rounded-md px-2 py-2 hover:bg-accent"><div className="min-w-0"><p className="truncate text-sm">{a.name}</p><p className="text-xs text-muted-foreground">{a.provider}/{a.model_name} · {timeAgo(a.created_at)}</p></div><div className="flex items-center gap-3">{a.score?.overall != null && <span className={`text-sm font-semibold tabular-nums ${scoreColor(a.score.overall)}`}>{a.score.overall}</span>}<StatusBadge status={a.status} /></div></Link>)}</CardContent></Card>
      <Card><CardHeader><CardTitle>Recently discovered vulnerabilities</CardTitle></CardHeader><CardContent className="space-y-1">{d.recent.vulnerabilities.length === 0 && <p className="px-2 text-sm text-muted-foreground">None yet.</p>}{d.recent.vulnerabilities.map((v: any) => <Link key={v.id} href={`/vulnerabilities/${v.id}`} className="flex items-center justify-between gap-2 rounded-md px-2 py-2 hover:bg-accent"><div className="min-w-0"><p className="truncate text-sm">{v.title}</p><p className="text-xs text-muted-foreground">{v.finding_id} · {timeAgo(v.detected_at)}</p></div><SeverityBadge severity={v.severity} /></Link>)}</CardContent></Card>
      <Card><CardHeader><CardTitle>Recent reports</CardTitle></CardHeader><CardContent className="space-y-1">{d.recent.reports.length === 0 && <p className="px-2 text-sm text-muted-foreground">No reports generated yet.</p>}{d.recent.reports.map((r: any) => <Link key={r.id} href="/reports" className="flex items-center justify-between rounded-md px-2 py-2 hover:bg-accent"><span className="truncate text-sm">{r.name}</span><span className="text-xs uppercase text-muted-foreground">{r.format} v{r.version}</span></Link>)}</CardContent></Card>
      <Card><CardHeader><CardTitle>Account activity & notifications</CardTitle></CardHeader><CardContent className="space-y-1.5 text-sm">
        {d.recent.notifications.map((n: any) => <Link key={n.id} href={n.link ?? "/notifications"} className="block rounded-md px-2 py-1.5 hover:bg-accent"><p className={n.read ? "text-muted-foreground" : ""}>{n.title}</p><p className="text-xs text-muted-foreground">{timeAgo(n.created_at)}</p></Link>)}
        <div className="border-t pt-2">{d.recent.account_activity.map((h: any) => <p key={h.id} className="px-2 py-0.5 text-xs text-muted-foreground">{h.success ? "Sign-in" : "Failed sign-in"} · {h.ip} · {fmtDate(h.ts)}</p>)}</div></CardContent></Card></div></>;
}
