"use client";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { Download, FileText, Pause, Play, RotateCcw, Square, Trash2, AlertTriangle } from "lucide-react";
import { Button, Card, CardContent, CardHeader, CardTitle, CardDescription, Dialog, DialogContent, Progress, Select, Skeleton, Table, Tabs, TabsContent, TabsList, TabsTrigger, Td, Th, Tr } from "@/components/ui/primitives";
import { ConfirmDialog, EmptyState, PageHeader, Pagination, ScoreRing, SeverityBadge, StatCard, StatusBadge, TableSkeleton } from "@/components/shared";
import { api, ApiError, download } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { CATEGORY_LABELS, fmtDate, pct, scoreColor, cn } from "@/lib/utils";

const ACTIVE = ["queued", "running", "pausing", "cancelling"];

export default function AssessmentDetail() {
  const { id } = useParams<{ id: string }>(); const router = useRouter(); const { can, me } = useAuth();
  const a = useApi<any>(`/assessments/${id}`, undefined, { poll: 4000 });
  const active = a.data && ACTIVE.includes(a.data.status);
  const prog = useApi<any>(`/assessments/${id}/progress`, undefined, { poll: active ? 2000 : 0 });
  const [busy, setBusy] = useState(""); const [del, setDel] = useState(false); const [cancel, setCancel] = useState(false);
  if (a.error) return <EmptyState icon={AlertTriangle} title="Assessment not found" description="It may have been deleted or you may not have access." action={<Button asChild variant="outline"><Link href="/assessments">Back to assessments</Link></Button>} />;
  if (!a.data) return <div className="space-y-4"><Skeleton className="h-8 w-72" /><Skeleton className="h-40" /><Skeleton className="h-64" /></div>;
  const x = a.data; const p = prog.data; const sc = x.score; const write = can("assessment:write");
  const act = async (name: string, path: string, msg: string) => { setBusy(name); try { await api(`/assessments/${id}/${path}`, { method: "POST" }); toast.success(msg); a.reload(); prog.reload(); } catch (e) { toast.error((e as ApiError).message); } finally { setBusy(""); } };
  return <><PageHeader title={x.name} crumbs={[{ label: "Assessments", href: "/assessments" }, { label: x.name }]} description={`${x.provider}/${x.model_name} · intensity ${x.intensity} · created ${fmtDate(x.created_at)}`}
    actions={<><StatusBadge status={x.status} />
      {write && x.status === "draft" && <Button loading={busy === "start"} onClick={() => act("start", "start", "Assessment queued")}><Play className="h-4 w-4" />Start</Button>}
      {write && ["running", "queued"].includes(x.status) && <Button variant="outline" loading={busy === "pause"} onClick={() => act("pause", "pause", "Pause requested")}><Pause className="h-4 w-4" />Pause</Button>}
      {write && x.status === "paused" && <Button loading={busy === "resume"} onClick={() => act("resume", "resume", "Resumed")}><Play className="h-4 w-4" />Resume</Button>}
      {write && ["running", "queued", "paused", "pausing"].includes(x.status) && <Button variant="outline" onClick={() => setCancel(true)}><Square className="h-4 w-4" />Cancel</Button>}
      {write && !ACTIVE.includes(x.status) && <Button variant="ghost" size="icon" onClick={() => setDel(true)} aria-label="Delete assessment"><Trash2 className="h-4 w-4 text-danger" /></Button>}</>} />
    {x.status === "failed" && <div role="alert" className="mb-4 rounded-md border border-danger/30 bg-danger/10 p-3 text-sm text-danger">Assessment failed: {x.error}</div>}
    <Tabs defaultValue="overview"><TabsList><TabsTrigger value="overview">Overview</TabsTrigger><TabsTrigger value="tests">Tests</TabsTrigger><TabsTrigger value="findings">Findings</TabsTrigger><TabsTrigger value="logs">Logs</TabsTrigger><TabsTrigger value="reports">Reports</TabsTrigger></TabsList>
      <TabsContent value="overview"><Overview x={x} p={p} sc={sc} /></TabsContent>
      <TabsContent value="tests"><Tests id={id} write={write} status={x.status} onChange={() => { a.reload(); prog.reload(); }} /></TabsContent>
      <TabsContent value="findings"><Findings id={id} /></TabsContent>
      <TabsContent value="logs"><Logs id={id} live={!!active} /></TabsContent>
      <TabsContent value="reports"><Reports id={id} status={x.status} formats={me?.plan.report_formats ?? []} write={can("report:write")} /></TabsContent></Tabs>
    <ConfirmDialog open={cancel} onOpenChange={setCancel} title="Cancel assessment?" description="Remaining tests will be marked not tested. Completed results are kept." confirmLabel="Cancel assessment" destructive onConfirm={() => act("cancel", "cancel", "Cancellation requested")} />
    <ConfirmDialog open={del} onOpenChange={setDel} title="Delete assessment?" description="This permanently deletes the assessment, its findings and reports." confirmLabel="Delete" destructive onConfirm={async () => { await api(`/assessments/${id}`, { method: "DELETE" }); toast.success("Deleted"); router.replace("/assessments"); }} /></>;
}

function Overview({ x, p, sc }: { x: any; p: any; sc: any }) {
  return <div className="space-y-4">
    {(ACTIVE.includes(x.status) || x.status === "paused") && p && <Card><CardHeader><CardTitle>Execution progress</CardTitle><CardDescription>{p.finished} of {p.total} tests finished{p.running?.length ? ` · running ${p.running.join(", ")}` : ""}</CardDescription></CardHeader><CardContent className="space-y-3"><Progress value={p.percent} />
      <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">{Object.entries(p.counts as Record<string, number>).map(([k, v]) => <span key={k}><StatusBadge status={k} /> <span className="tabular-nums">{v}</span></span>)}</div>
      <p className="text-xs text-muted-foreground">Requests used {p.usage?.requests ?? 0} / {p.limits?.max_requests} · tokens {p.usage?.tokens ?? 0}</p></CardContent></Card>}
    {sc ? <>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3"><Card className="flex flex-col items-center justify-center gap-2 p-6"><ScoreRing score={sc.overall} size={140} label={sc.grade} />{sc.provisional && <p className="text-center text-xs text-warning">Provisional: coverage {pct(sc.coverage)} (&lt; 60%)</p>}{sc.cap_applied && <p className="text-center text-xs text-muted-foreground">Capped at {sc.cap_applied} by severity rules</p>}</Card>
        <div className="grid grid-cols-2 gap-3 lg:col-span-2"><StatCard label="Vulnerabilities" value={sc.vulnerability_count} tone={sc.vulnerability_count ? "text-danger" : ""} /><StatCard label="Test coverage" value={pct(sc.coverage)} hint={`${sc.tested} of ${sc.selected} tested`} /><StatCard label="Passed / Failed" value={`${sc.passed} / ${sc.failed}`} /><StatCard label="Detection confidence" value={sc.detection_confidence != null ? pct(sc.detection_confidence) : "—"} hint={`${sc.inconclusive} inconclusive · ${sc.not_tested} not tested`} /></div></div>
      <Card><CardHeader><CardTitle>Executive summary</CardTitle></CardHeader><CardContent><p className="text-sm leading-relaxed text-muted-foreground">{x.summary}</p></CardContent></Card>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card><CardHeader><CardTitle>Risk distribution</CardTitle></CardHeader><CardContent className="flex flex-wrap gap-3">{Object.entries(sc.risk_distribution as Record<string, number>).map(([s, n]) => <div key={s} className="flex items-center gap-2"><SeverityBadge severity={s} /><span className="tabular-nums">{n}</span></div>)}</CardContent></Card>
        <Card><CardHeader><CardTitle>Category scores</CardTitle><CardDescription>Not tested categories are never shown as secure.</CardDescription></CardHeader><CardContent className="space-y-2.5">{Object.entries(sc.categories as Record<string, any>).map(([k, v]) => <div key={k}><div className="mb-1 flex justify-between text-xs"><span>{CATEGORY_LABELS[k]}</span><span className={cn("tabular-nums font-medium", scoreColor(v.score))}>{v.score ?? "not tested"}</span></div><Progress value={v.score ?? 0} color={v.score == null ? "transparent" : undefined} /><p className="mt-0.5 text-[10px] text-muted-foreground">{v.tested} tested · {v.failed} failed · {v.inconclusive} inconclusive · {v.not_tested} not tested</p></div>)}</CardContent></Card></div></> :
      !ACTIVE.includes(x.status) && x.status !== "paused" && <EmptyState title={x.status === "draft" ? "Draft – not started" : "No results"} description={x.status === "draft" ? "Press Start to queue this assessment." : "This assessment produced no score."} />}
    <Card><CardHeader><CardTitle>Configuration</CardTitle></CardHeader><CardContent className="grid gap-3 text-sm sm:grid-cols-2"><Row k="Provider" v={x.provider} /><Row k="Model" v={x.model_name} /><Row k="Endpoint" v={x.endpoint ?? "provider default"} /><Row k="Intensity" v={x.intensity} /><Row k="Request budget" v={x.limits.max_requests} /><Row k="Timeout / retries" v={`${x.limits.timeout}s / ${x.limits.retries}`} /><Row k="Selected attacks" v={x.attack_ids.length} /><Row k="AI analysis" v={x.ai_analysis ? "enabled" : "off"} /><div className="sm:col-span-2"><Row k="Authorisation" v={x.authorization?.statement} /></div></CardContent></Card></div>;
}
const Row = ({ k, v }: { k: string; v: any }) => <div><p className="text-xs text-muted-foreground">{k}</p><p className="break-words">{String(v)}</p></div>;

function Tests({ id, write, status, onChange }: { id: string; write: boolean; status: string; onChange: () => void }) {
  const [st, setSt] = useState(""); const [cat, setCat] = useState(""); const [page, setPage] = useState(1); const [open, setOpen] = useState<string | null>(null);
  const d = useApi<any>(`/assessments/${id}/executions`, { status: st, category: cat, page, size: 25 }, { poll: ACTIVE.includes(status) ? 3000 : 0 });
  return <><div className="mb-3 flex flex-wrap gap-2"><Select className="w-40" value={st} onChange={(e) => { setSt(e.target.value); setPage(1); }} aria-label="Filter by result"><option value="">All results</option>{["passed", "failed", "inconclusive", "error", "skipped", "queued", "running"].map((s) => <option key={s} value={s}>{s === "skipped" ? "not tested" : s}</option>)}</Select>
    <Select className="w-52" value={cat} onChange={(e) => { setCat(e.target.value); setPage(1); }} aria-label="Filter by category"><option value="">All categories</option>{Object.entries(CATEGORY_LABELS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</Select></div>
    <Card>{!d.data ? <TableSkeleton /> : <Table><thead><tr className="border-b"><Th>Test</Th><Th>Category</Th><Th>Result</Th><Th>Confidence</Th><Th>Detection</Th><Th /></tr></thead><tbody>{d.data.items.map((e: any) => <Tr key={e.id}><Td><p className="font-medium">{e.attack_name ?? e.attack_id}</p><p className="font-mono text-xs text-muted-foreground">{e.attack_id}</p></Td><Td className="text-muted-foreground">{CATEGORY_LABELS[e.category]}</Td><Td><StatusBadge status={e.status} />{e.reason && <p className="mt-0.5 text-[10px] text-muted-foreground">{e.reason}</p>}</Td><Td className="tabular-nums">{e.confidence ? pct(e.confidence) : "—"}</Td><Td className="text-xs text-muted-foreground">{e.detection?.method ?? "—"}</Td>
      <Td className="text-right whitespace-nowrap"><Button size="sm" variant="ghost" onClick={() => setOpen(e.id)} disabled={!e.finished_at}>Details</Button>{write && ["error", "inconclusive"].includes(e.status) && !ACTIVE.includes(status) && <Button size="sm" variant="ghost" onClick={async () => { try { await api(`/assessments/${id}/executions/${e.id}/retry`, { method: "POST" }); toast.success("Retry queued"); onChange(); d.reload(); } catch (x) { toast.error((x as ApiError).message); } }}><RotateCcw className="h-3 w-3" />Retry</Button>}</Td></Tr>)}</tbody></Table>}
      {d.data && <div className="px-4 pb-3"><Pagination page={page} size={25} total={d.data.total} onPage={setPage} /></div>}</Card>
    <ExecDialog id={id} eid={open} onClose={() => setOpen(null)} /></>;
}

function ExecDialog({ id, eid, onClose }: { id: string; eid: string | null; onClose: () => void }) {
  const d = useApi<any>(eid ? `/assessments/${id}/executions/${eid}` : null);
  return <Dialog open={!!eid} onOpenChange={(o) => !o && onClose()}><DialogContent title={d.data?.attack?.name ?? "Test details"} description={d.data ? `${d.data.attack_id} · ${d.data.status}` : ""} className="max-w-2xl">
    {!d.data ? <Skeleton className="h-40" /> : <div className="space-y-3 text-sm">
      <div className="grid grid-cols-2 gap-2 text-xs"><div><span className="text-muted-foreground">Expected secure:</span> {d.data.attack?.expected_secure}</div><div><span className="text-muted-foreground">Expected vulnerable:</span> {d.data.attack?.expected_vulnerable}</div></div>
      <p className="text-xs"><span className="text-muted-foreground">Detection:</span> {d.data.detection?.method} · {d.data.detection?.reason}</p>
      {d.data.transcript ? <>
        <Block title="System (harness)" text={d.data.transcript.system} />{d.data.transcript.messages.map((m: any, i: number) => <Block key={i} title={m.role} text={m.content} />)}
        {d.data.transcript.responses.map((r: any, i: number) => <Block key={i} title={`Response · ${r.status} · ${r.latency_ms} ms`} text={r.text || (r.tool_calls.length ? "" : r.error || "(empty)")} tools={r.tool_calls} />)}</> : <p className="text-muted-foreground">No transcript recorded.</p>}
      <p className="text-[11px] text-muted-foreground">Evidence is redacted; secrets and personal data are never stored.</p></div>}</DialogContent></Dialog>;
}
const Block = ({ title, text, tools }: { title: string; text: string; tools?: any[] }) => <div><p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">{title}</p><pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-background p-2 font-mono text-xs">{text}{tools?.map((t, i) => `\n→ tool_call ${t.name}(${t.arguments})`)}</pre></div>;

function Findings({ id }: { id: string }) {
  const d = useApi<any>("/vulnerabilities", { assessment_id: id, sort: "severity", size: 100 });
  if (!d.data) return <TableSkeleton />;
  if (!d.data.items.length) return <EmptyState title="No findings" description="No vulnerabilities were detected by the executed tests. This does not prove the absence of vulnerabilities." />;
  return <Card><Table><thead><tr className="border-b"><Th>Finding</Th><Th>Severity</Th><Th>Category</Th><Th>Confidence</Th><Th>Status</Th></tr></thead><tbody>{d.data.items.map((v: any) => <Tr key={v.id}><Td><Link href={`/vulnerabilities/${v.id}`} className="font-medium hover:text-primary">{v.title}</Link><p className="font-mono text-xs text-muted-foreground">{v.finding_id}</p></Td><Td><SeverityBadge severity={v.severity} /></Td><Td className="text-muted-foreground">{CATEGORY_LABELS[v.category]}</Td><Td className="tabular-nums">{pct(v.confidence)}</Td><Td><StatusBadge status={v.triage === "needs_review" ? "needs_review" : v.status} /></Td></Tr>)}</tbody></Table></Card>;
}

function Logs({ id, live }: { id: string; live: boolean }) {
  const d = useApi<any[]>(`/assessments/${id}/logs`, undefined, { poll: live ? 3000 : 0 });
  const [fmt, setFmt] = useState("json");
  return <Card><CardHeader className="flex-row items-center justify-between"><CardTitle>Execution log</CardTitle><div className="flex items-center gap-2"><Select className="h-8 w-24 text-xs" value={fmt} onChange={(e) => setFmt(e.target.value)} aria-label="Export format"><option value="json">JSON</option><option value="csv">CSV</option></Select><Button size="sm" variant="outline" onClick={() => download(`/assessments/${id}/export?format=${fmt}`).catch(() => toast.error("Export failed"))}><Download className="h-3 w-3" />Export findings</Button></div></CardHeader>
    <CardContent><div className="max-h-[28rem] overflow-auto rounded-md border bg-background p-3 font-mono text-xs">{!d.data ? <Skeleton className="h-24" /> : d.data.map((l, i) => <p key={i} className={cn(l.level === "error" && "text-danger", l.level === "warn" && "text-warning", "py-0.5")}><span className="text-muted-foreground">{new Date(l.ts).toLocaleTimeString()}</span> {l.message}</p>)}</div></CardContent></Card>;
}

function Reports({ id, status, formats, write }: { id: string; status: string; formats: string[]; write: boolean }) {
  const d = useApi<any>("/reports", { assessment_id: id }); const [fmt, setFmt] = useState("html"); const [busy, setBusy] = useState(false);
  const ready = ["completed", "cancelled", "failed"].includes(status);
  return <Card><CardHeader className="flex-row items-center justify-between"><div><CardTitle>Reports</CardTitle><CardDescription>{ready ? "Generate a downloadable report." : "Available once the assessment finishes."}</CardDescription></div>
    {write && <div className="flex gap-2"><Select className="h-8 w-28 text-xs" value={fmt} onChange={(e) => setFmt(e.target.value)} aria-label="Report format">{["html", "pdf", "json", "csv"].map((f) => <option key={f} value={f} disabled={!formats.includes(f)}>{f.toUpperCase()}{formats.includes(f) ? "" : " (upgrade)"}</option>)}</Select>
      <Button size="sm" disabled={!ready} loading={busy} onClick={async () => { setBusy(true); try { await api(`/assessments/${id}/reports`, { method: "POST", body: { format: fmt } }); toast.success("Report generated"); d.reload(); } catch (e) { toast.error((e as ApiError).message); } finally { setBusy(false); } }}><FileText className="h-3 w-3" />Generate</Button></div>}</CardHeader>
    <CardContent>{!d.data ? <Skeleton className="h-16" /> : !d.data.items.length ? <p className="text-sm text-muted-foreground">No reports yet.</p> : <ul className="divide-y">{d.data.items.map((r: any) => <li key={r.id} className="flex items-center justify-between py-2 text-sm"><span>{r.report_id} · v{r.version} · <span className="uppercase">{r.format}</span> <span className="text-xs text-muted-foreground">· {fmtDate(r.created_at)} · {(r.size / 1024).toFixed(0)} KB</span></span><Button size="sm" variant="outline" onClick={() => download(`/reports/${r.id}/download`).catch(() => toast.error("Download failed"))}><Download className="h-3 w-3" />Download</Button></li>)}</ul>}</CardContent></Card>;
}
