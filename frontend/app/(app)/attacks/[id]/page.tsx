"use client";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { AlertTriangle, Lock, Trash2 } from "lucide-react";
import { Button, Card, CardContent, CardHeader, CardTitle, Skeleton } from "@/components/ui/primitives";
import { ConfirmDialog, EmptyState, PageHeader, SeverityBadge, StatusBadge } from "@/components/shared";
import { api } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { CATEGORY_LABELS, fmtDate } from "@/lib/utils";

export default function AttackDetail() {
  const { id } = useParams<{ id: string }>(); const router = useRouter(); const { can } = useAuth(); const d = useApi<any>(`/attacks/${id}`); const h = useApi<any>(`/attacks/${id}/history`); const [del, setDel] = useState(false);
  if (d.error) return <EmptyState icon={AlertTriangle} title="Attack not found" action={<Button asChild variant="outline"><Link href="/attacks">Back</Link></Button>} />;
  if (!d.data) return <Skeleton className="h-96" />;
  const a = d.data;
  return <><PageHeader title={a.name} crumbs={[{ label: "Attack library", href: "/attacks" }, { label: a.attack_id }]} description={a.description} actions={<><SeverityBadge severity={a.risk} />{a.source === "custom" && can("attack:write") && <Button variant="ghost" size="icon" onClick={() => setDel(true)} aria-label="Delete attack"><Trash2 className="h-4 w-4 text-danger" /></Button>}</>} />
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3"><div className="space-y-4 lg:col-span-2">
      {a.locked ? <Card className="p-5"><p className="flex items-center gap-2 text-sm"><Lock className="h-4 w-4 text-warning" />This advanced module’s procedure is available on the Researcher plan and above.</p></Card> : <Card><CardHeader><CardTitle>Test procedure</CardTitle></CardHeader><CardContent className="space-y-2">
        {a.dos ? <p className="text-sm text-muted-foreground">Bounded {a.dos.kind.replace("_", " ")} probe (size determined by assessment intensity).</p> : a.turns.map((t: any, i: number) => <pre key={i} className="whitespace-pre-wrap break-words rounded-md border bg-background p-2 font-mono text-xs"><span className="text-muted-foreground">{typeof t === "string" ? "user" : t.role}: </span>{typeof t === "string" ? t : t.content}</pre>)}</CardContent></Card>}
      <div className="grid gap-4 sm:grid-cols-2"><Card><CardHeader><CardTitle>Expected secure behaviour</CardTitle></CardHeader><CardContent className="text-sm text-muted-foreground">{a.expected_secure}</CardContent></Card><Card><CardHeader><CardTitle>Expected vulnerable behaviour</CardTitle></CardHeader><CardContent className="text-sm text-muted-foreground">{a.expected_vulnerable}</CardContent></Card></div>
      {!a.locked && <Card><CardHeader><CardTitle>Detection logic</CardTitle></CardHeader><CardContent className="space-y-2">{a.detect.map((r: any, i: number) => <p key={i} className="rounded-md border bg-background p-2 text-xs"><b>{r.type}</b>{r.soft ? " (heuristic, needs review)" : ""}{r.patterns?.length ? ` — ${r.patterns.join(" | ").slice(0, 160)}` : ""}{r.names?.length ? ` — tools: ${r.names.join(", ")}` : ""}</p>)}<p className="text-xs text-muted-foreground">Evidence: {a.evidence}</p></CardContent></Card>}
      <Card><CardHeader><CardTitle>Remediation guidance</CardTitle></CardHeader><CardContent className="text-sm text-muted-foreground">{a.remediation}</CardContent></Card></div>
    <div className="space-y-4"><Card><CardHeader><CardTitle>Metadata</CardTitle></CardHeader><CardContent className="space-y-2 text-sm"><M k="ID" v={a.attack_id} /><M k="Category" v={CATEGORY_LABELS[a.category]} /><M k="Tier" v={a.tier} /><M k="OWASP" v={a.owasp.join(", ") || "—"} /><M k="CWE" v={a.cwe.join(", ") || "—"} /><M k="MITRE ATLAS" v={a.atlas.join(", ") || "—"} /><M k="CVSS vector" v={a.cvss_vector ?? "n/a"} /><M k="Version" v={a.version} /></CardContent></Card>
      <Card><CardHeader><CardTitle>Execution history</CardTitle></CardHeader><CardContent className="space-y-2 text-sm">{h.data && <><div className="flex flex-wrap gap-2">{Object.entries(h.data.summary as Record<string, number>).map(([k, v]) => <span key={k} className="flex items-center gap-1"><StatusBadge status={k} />{v}</span>)}{!Object.keys(h.data.summary).length && <span className="text-muted-foreground">Not executed yet.</span>}</div>
        {h.data.recent.slice(0, 6).map((e: any) => <Link key={e.id} href={`/assessments/${e.assessment_id}`} className="flex items-center justify-between rounded px-1 py-1 text-xs hover:bg-accent"><StatusBadge status={e.status} /><span className="text-muted-foreground">{fmtDate(e.finished_at)}</span></Link>)}</>}</CardContent></Card></div></div>
    <ConfirmDialog open={del} onOpenChange={setDel} title="Delete custom attack?" description="Existing findings are kept." destructive confirmLabel="Delete" onConfirm={async () => { await api(`/attacks/${id}`, { method: "DELETE" }); toast.success("Deleted"); router.replace("/attacks"); }} /></>;
}
const M = ({ k, v }: { k: string; v: any }) => <div className="flex justify-between gap-3"><span className="text-muted-foreground">{k}</span><span className="break-all text-right">{String(v)}</span></div>;
