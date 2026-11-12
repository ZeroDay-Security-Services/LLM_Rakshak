"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Lock, ShieldCheck } from "lucide-react";
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Field, Input, Select, Switch, Textarea } from "@/components/ui/primitives";
import { EmptyState, ErrorNote, PageHeader, SeverityBadge } from "@/components/shared";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { CATEGORY_LABELS, cn } from "@/lib/utils";

const PRESETS = [
  { key: "quick", title: "Quick scan", body: "Prompt injection, system prompt and disclosure (basic modules)." },
  { key: "standard", title: "Standard", body: "All ten categories, basic modules." },
  { key: "full", title: "Full", body: "All categories including advanced modules (Researcher+)." },
];

export default function NewAssessment() {
  const router = useRouter(); const { me } = useAuth();
  const models = useApi<any>("/models", { size: 100 }); const cats = useApi<any[]>("/attacks/categories");
  const [mode, setMode] = useState<"preset" | "custom">("preset"); const [preset, setPreset] = useState("standard"); const [selCats, setSelCats] = useState<string[]>([]);
  const [selAttacks, setSelAttacks] = useState<string[]>([]); const [showAttacks, setShowAttacks] = useState(false);
  const attacks = useApi<any>(showAttacks ? "/attacks" : null, { size: 100 });
  const [f, setF] = useState({ name: "", model: "", intensity: "medium", max_requests: 120, timeout: 45, retries: 2, system_prompt: "", ai: false, notes: "" });
  const [auth, setAuth] = useState({ confirmed: false, owner: false, statement: "" }); const [err, setErr] = useState<ApiError | null>(null); const [busy, setBusy] = useState<"" | "draft" | "start">("");
  const model = models.data?.items.find((m: any) => m.id === f.model); const customEndpoint = model && ["custom", "openai_compatible"].includes(model.provider);
  const plan = me?.plan; const maxReq = plan?.max_requests_per_assessment ?? 120;
  const valid = f.name.trim() && f.model && auth.confirmed && auth.statement.trim().length >= 20 && (!customEndpoint || auth.owner) && f.max_requests <= maxReq && (mode === "preset" || selCats.length > 0 || selAttacks.length > 0);
  const set = (k: string, v: any) => setF((p) => ({ ...p, [k]: v }));

  async function submit(start: boolean) {
    setErr(null); setBusy(start ? "start" : "draft");
    try {
      const body: any = { name: f.name.trim(), model_config_id: f.model, intensity: f.intensity, limits: { max_requests: f.max_requests, timeout: f.timeout, retries: f.retries }, ai_analysis: f.ai, notes: f.notes,
        system_prompt: f.system_prompt || undefined, authorization: { confirmed: auth.confirmed, statement: auth.statement.trim(), endpoint_owner_confirmed: auth.owner } };
      if (mode === "preset") body.preset = preset; else if (selAttacks.length) body.attack_ids = selAttacks; else body.categories = selCats;
      const a = await api<any>("/assessments", { method: "POST", body });
      if (start) { await api(`/assessments/${a.id}/start`, { method: "POST" }); toast.success("Assessment queued"); } else toast.success("Draft saved");
      if (a.excluded_by_plan) toast.message(`${a.excluded_by_plan} advanced module(s) excluded by your plan`);
      router.push(`/assessments/${a.id}`);
    } catch (x) { setErr(x as ApiError); window.scrollTo({ top: 0, behavior: "smooth" }); } finally { setBusy(""); }
  }
  if (models.data && models.data.items.length === 0) return <><PageHeader title="New assessment" crumbs={[{ label: "Assessments", href: "/assessments" }, { label: "New" }]} /><EmptyState title="Add a model first" description="An assessment needs a configured target model." action={<Button asChild><Link href="/models">Configure a model</Link></Button>} /></>;
  const toggle = (arr: string[], v: string, set: (a: string[]) => void) => set(arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);
  return <><PageHeader title="New assessment" description="Configure the target, scope and limits. Nothing runs until you start it." crumbs={[{ label: "Assessments", href: "/assessments" }, { label: "New" }]} />
    <div className="mx-auto max-w-3xl space-y-4"><ErrorNote error={err} />
      <Card><CardHeader><CardTitle>Target</CardTitle></CardHeader><CardContent className="grid gap-4 sm:grid-cols-2">
        <Field label="Assessment name"><Input value={f.name} onChange={(e) => set("name", e.target.value)} maxLength={120} placeholder="Support bot – pre-release" /></Field>
        <Field label="Target model" hint={model ? `${model.provider} · ${model.model}` : undefined}><Select value={f.model} onChange={(e) => set("model", e.target.value)}><option value="">Select a model…</option>{models.data?.items.map((m: any) => <option key={m.id} value={m.id}>{m.name} ({m.provider})</option>)}</Select></Field>
        <div className="sm:col-span-2"><Field label="System prompt override (optional)" hint="Defaults to the model’s configured system prompt. Used for prompt-extraction similarity checks."><Textarea value={f.system_prompt} onChange={(e) => set("system_prompt", e.target.value)} maxLength={8000} rows={3} placeholder="Leave empty to use the model configuration" /></Field></div></CardContent></Card>
      <Card><CardHeader><CardTitle>Scope</CardTitle><CardDescription>Choose a preset or build a custom selection.</CardDescription></CardHeader><CardContent className="space-y-4">
        <div className="inline-flex rounded-md bg-muted p-1 text-sm">{(["preset", "custom"] as const).map((m) => <button key={m} onClick={() => setMode(m)} className={cn("rounded px-3 py-1 capitalize", mode === m ? "bg-card shadow" : "text-muted-foreground")}>{m === "preset" ? "Preset" : "Custom selection"}</button>)}</div>
        {mode === "preset" ? <div className="grid gap-2 sm:grid-cols-3">{PRESETS.map((p) => { const locked = p.key === "full" && !plan?.tiers.includes("advanced"); return <button key={p.key} type="button" onClick={() => setPreset(p.key)} className={cn("rounded-lg border p-3 text-left transition-colors", preset === p.key ? "border-primary bg-primary/10" : "hover:bg-accent")}><p className="flex items-center gap-1 text-sm font-medium">{p.title}{locked && <Lock className="h-3 w-3 text-warning" />}</p><p className="mt-1 text-xs text-muted-foreground">{locked ? "Advanced modules need the Researcher plan; basic ones will run." : p.body}</p></button>; })}</div> :
          <div className="space-y-3"><div className="grid gap-2 sm:grid-cols-2">{cats.data?.map((c) => <label key={c.key} className="flex cursor-pointer items-center gap-2 rounded-md border p-2 text-sm hover:bg-accent"><input type="checkbox" className="accent-[hsl(var(--primary))]" checked={selCats.includes(c.key)} onChange={() => toggle(selCats, c.key, setSelCats)} disabled={selAttacks.length > 0} />{c.label}<span className="ml-auto text-xs text-muted-foreground">{c.count}</span></label>)}</div>
            <Button variant="outline" size="sm" onClick={() => setShowAttacks(!showAttacks)}>{showAttacks ? "Hide" : "Pick individual"} attacks{selAttacks.length ? ` (${selAttacks.length})` : ""}</Button>
            {showAttacks && <div className="max-h-64 space-y-1 overflow-y-auto rounded-md border p-2">{attacks.data?.items.map((a: any) => <label key={a.attack_id} className={cn("flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-accent", a.locked && "opacity-50")}><input type="checkbox" disabled={a.locked} checked={selAttacks.includes(a.attack_id)} onChange={() => toggle(selAttacks, a.attack_id, setSelAttacks)} /><span className="font-mono text-xs text-muted-foreground">{a.attack_id}</span><span className="truncate">{a.name}</span><span className="ml-auto flex items-center gap-2">{a.locked && <Lock className="h-3 w-3" />}<SeverityBadge severity={a.risk} /></span></label>)}</div>}</div>}</CardContent></Card>
      <Card><CardHeader><CardTitle>Intensity & limits</CardTitle><CardDescription>Hard caps protect your target and your provider bill.</CardDescription></CardHeader><CardContent className="grid gap-4 sm:grid-cols-2">
        <Field label="Intensity" hint="Controls concurrency, pacing and DoS payload size."><Select value={f.intensity} onChange={(e) => set("intensity", e.target.value)}><option value="low">Low – sequential, paced</option><option value="medium">Medium</option><option value="high">High – parallel</option></Select></Field>
        <Field label={`Maximum requests (plan cap ${maxReq})`} error={f.max_requests > maxReq ? "Exceeds your plan limit" : undefined}><Input type="number" min={5} max={5000} value={f.max_requests} onChange={(e) => set("max_requests", Number(e.target.value))} /></Field>
        <Field label="Request timeout (s)"><Input type="number" min={5} max={120} value={f.timeout} onChange={(e) => set("timeout", Number(e.target.value))} /></Field>
        <Field label="Retries on transient errors"><Select value={f.retries} onChange={(e) => set("retries", Number(e.target.value))}>{[0, 1, 2, 3].map((n) => <option key={n} value={n}>{n}</option>)}</Select></Field>
        <div className="flex items-center justify-between rounded-md border p-3 sm:col-span-2"><div><p className="text-sm font-medium">AI-assisted analysis</p><p className="text-xs text-muted-foreground">{plan?.ai_analysis ? "Claude reviews ambiguous results and writes the executive summary. Needs an Anthropic key or platform key." : "Available on the Researcher plan and above."}</p></div><Switch checked={f.ai && !!plan?.ai_analysis} onCheckedChange={(v) => set("ai", v)} disabled={!plan?.ai_analysis} aria-label="AI-assisted analysis" /></div></CardContent></Card>
      <Card className="border-warning/40"><CardHeader><CardTitle className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-warning" />Authorisation</CardTitle><CardDescription>Required. This is stored with the assessment and audit-logged.</CardDescription></CardHeader><CardContent className="space-y-3">
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={auth.confirmed} onChange={(e) => setAuth({ ...auth, confirmed: e.target.checked })} />I own this system or have explicit written authorisation to run security tests against it.</label>
        {customEndpoint && <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={auth.owner} onChange={(e) => setAuth({ ...auth, owner: e.target.checked })} />I confirm I own or am authorised to test this custom endpoint (<span className="font-mono text-xs">{model.endpoint}</span>).</label>}
        <Field label="Authorisation statement" hint="At least 20 characters, e.g. who authorised it and the scope."><Textarea rows={2} maxLength={1000} value={auth.statement} onChange={(e) => setAuth({ ...auth, statement: e.target.value })} placeholder="Approved by Jane Doe (CISO) on 2026-11-01 for pre-release testing of the support bot." /></Field></CardContent></Card>
      <div className="flex flex-wrap justify-end gap-2 pb-8"><Button variant="outline" disabled={!valid} loading={busy === "draft"} onClick={() => submit(false)}>Save draft</Button><Button disabled={!valid} loading={busy === "start"} onClick={() => submit(true)}>Create & start</Button></div></div></>;
}
