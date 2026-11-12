"use client";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { AlertTriangle, RotateCcw } from "lucide-react";
import { Button, Card, CardContent, CardHeader, CardTitle, Select, Skeleton, Textarea } from "@/components/ui/primitives";
import { EmptyState, PageHeader, SeverityBadge, StatusBadge } from "@/components/shared";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { CATEGORY_LABELS, fmtDate, pct } from "@/lib/utils";

const NEXT: Record<string, string[]> = { new: ["confirmed", "closed"], confirmed: ["in_progress", "closed"], in_progress: ["fixed", "confirmed"], fixed: ["retested", "in_progress"], retested: ["closed", "in_progress"], closed: ["new"] };

export default function VulnDetail() {
  const { id } = useParams<{ id: string }>(); const router = useRouter(); const { can } = useAuth(); const d = useApi<any>(`/vulnerabilities/${id}`);
  const [note, setNote] = useState(""); const [triage, setTriage] = useState(""); const [busy, setBusy] = useState("");
  if (d.error) return <EmptyState icon={AlertTriangle} title="Finding not found" action={<Button asChild variant="outline"><Link href="/vulnerabilities">Back</Link></Button>} />;
  if (!d.data) return <div className="space-y-4"><Skeleton className="h-8 w-80" /><Skeleton className="h-64" /></div>;
  const v = d.data; const write = can("finding:write");
  const run = async (key: string, fn: () => Promise<any>, ok: string) => { setBusy(key); try { await fn(); toast.success(ok); setNote(""); d.reload(); } catch (e) { toast.error((e as ApiError).message); } finally { setBusy(""); } };
  const ev = v.evidence?.transcript;
  return <><PageHeader title={v.title} crumbs={[{ label: "Vulnerabilities", href: "/vulnerabilities" }, { label: v.finding_id }]} description={`${CATEGORY_LABELS[v.category]} · ${v.model} · detected ${fmtDate(v.detected_at)}`} actions={<><SeverityBadge severity={v.severity} /><StatusBadge status={v.status} /></>} />
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3"><div className="space-y-4 lg:col-span-2">
      <Card><CardHeader><CardTitle>Description</CardTitle></CardHeader><CardContent className="space-y-3 text-sm text-muted-foreground"><p>{v.description}</p><div><p className="mb-1 text-xs font-semibold uppercase tracking-wide text-foreground">Impact</p><p>{v.impact}</p></div></CardContent></Card>
      <Card><CardHeader><CardTitle>Reproduction steps</CardTitle></CardHeader><CardContent><ol className="list-decimal space-y-2 pl-5 text-sm">{v.reproduction_steps.map((s: string, i: number) => <li key={i} className="break-words text-muted-foreground">{s}</li>)}</ol></CardContent></Card>
      <Card><CardHeader><CardTitle>Evidence (redacted)</CardTitle></CardHeader><CardContent className="space-y-3">
        {v.evidence?.matched_rules?.map((r: any, i: number) => <p key={i} className="rounded-md border bg-background p-2 text-xs"><b>{r.rule}</b> — {r.detail}</p>)}
        {ev?.messages?.map((m: any, i: number) => <div key={i}><p className="mb-1 text-[10px] font-semibold uppercase text-muted-foreground">{m.role}</p><pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-background p-2 font-mono text-xs">{m.content}</pre></div>)}
        {ev?.responses?.slice(0, 2).map((r: any, i: number) => <div key={i}><p className="mb-1 text-[10px] font-semibold uppercase text-muted-foreground">model response</p><pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-background p-2 font-mono text-xs">{r.text || "(no text)"}{r.tool_calls?.map((t: any) => `\n→ tool_call ${t.name}(${t.arguments})`)}</pre></div>)}</CardContent></Card>
      <Card><CardHeader><CardTitle>Remediation</CardTitle></CardHeader><CardContent><p className="text-sm text-muted-foreground">{v.remediation}</p></CardContent></Card></div>
    <div className="space-y-4">
      <Card><CardHeader><CardTitle>Details</CardTitle></CardHeader><CardContent className="space-y-2 text-sm"><KV k="Finding ID" v={v.finding_id} mono /><KV k="Confidence" v={pct(v.confidence)} /><KV k="Detection" v={`${v.detection.method}`} /><KV k="CVSS" v={v.cvss ? `${v.cvss.score} (${v.cvss.vector})` : "n/a"} /><KV k="OWASP" v={v.owasp.join(", ") || "—"} /><KV k="CWE" v={v.cwe.join(", ") || "—"} /><KV k="MITRE ATLAS" v={v.atlas.join(", ") || "—"} /><KV k="Triage" v={v.triage.replace("_", " ")} /><KV k="Assessment" v={<Link className="text-primary hover:underline" href={`/assessments/${v.assessment_id}`}>Open</Link>} /></CardContent></Card>
      {write && <Card><CardHeader><CardTitle>Workflow</CardTitle></CardHeader><CardContent className="space-y-3"><Textarea rows={2} maxLength={1000} placeholder="Optional note…" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Note" />
        <div className="flex flex-wrap gap-2">{NEXT[v.status].map((s) => <Button key={s} size="sm" variant="outline" disabled={s === "retested" && v.last_retest?.result !== "passed"} loading={busy === s} onClick={() => run(s, () => api(`/vulnerabilities/${id}/status`, { method: "PATCH", body: { status: s, note } }), `Moved to ${s.replace("_", " ")}`)}>→ {s.replace("_", " ")}</Button>)}</div>
        <div className="flex gap-2"><Select value={triage} onChange={(e) => setTriage(e.target.value)} aria-label="Triage decision"><option value="">Mark as…</option>{[["confirmed", "Confirmed"], ["false_positive", "False positive"], ["needs_review", "Needs review"], ["accepted_risk", "Accepted risk"], ["fixed", "Fixed"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</Select>
          <Button size="sm" disabled={!triage} loading={busy === "triage"} onClick={() => run("triage", () => api(`/vulnerabilities/${id}/triage`, { method: "PATCH", body: { triage, note } }), "Triage updated")}>Apply</Button></div>
        <Button variant="secondary" size="sm" className="w-full" loading={busy === "retest"} onClick={async () => { setBusy("retest"); try { const r = await api<any>(`/vulnerabilities/${id}/retest`, { method: "POST" }); toast.success("Retest queued"); router.push(`/assessments/${r.assessment_id}`); } catch (e) { toast.error((e as ApiError).message); } finally { setBusy(""); } }}><RotateCcw className="h-3 w-3" />Retest this finding</Button>
        {v.last_retest && <p className="text-xs text-muted-foreground">Last retest: <b>{v.last_retest.result}</b> · {fmtDate(v.last_retest.ts)}</p>}</CardContent></Card>}
      <Card><CardHeader><CardTitle>History</CardTitle></CardHeader><CardContent><ul className="space-y-2 text-xs">{[...v.history].reverse().map((h: any, i: number) => <li key={i} className="border-l-2 pl-3"><p>{h.event}{h.note ? ` — ${h.note}` : ""}</p><p className="text-muted-foreground">{fmtDate(h.ts)}</p></li>)}</ul></CardContent></Card></div></div></>;
}
const KV = ({ k, v, mono }: { k: string; v: any; mono?: boolean }) => <div className="flex justify-between gap-3"><span className="text-muted-foreground">{k}</span><span className={`text-right break-all ${mono ? "font-mono text-xs" : ""}`}>{v}</span></div>;
