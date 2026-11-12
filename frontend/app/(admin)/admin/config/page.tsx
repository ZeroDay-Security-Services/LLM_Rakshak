"use client";
import { useState } from "react";
import { toast } from "sonner";
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Field, Input, Select, Skeleton, Switch, Textarea } from "@/components/ui/primitives";
import { PageHeader } from "@/components/shared";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";

const PROVIDERS = [["anthropic", "Anthropic Claude"], ["openai", "OpenAI"], ["gemini", "Google Gemini"], ["openai_compatible", "OpenAI-compatible"], ["custom", "Custom self-hosted"]];
const FEATURES = [["ai_analysis", "AI-assisted analysis"], ["custom_attacks", "Custom attacks"], ["organizations", "Organizations & invitations"]];
export default function Config() {
  const { can } = useAuth(); const d = useApi<any>("/admin/settings"); const [ann, setAnn] = useState({ text: "", level: "info" }); const edit = can("admin:config");
  if (!d.data) return <Skeleton className="h-96" />;
  const c = d.data;
  const save = async (patch: any, msg = "Saved") => { try { const r = await api("/admin/settings", { method: "PUT", body: patch }); d.setData(r); toast.success(msg); } catch (e) { toast.error((e as ApiError).message); } };
  const toggleProvider = (k: string) => save({ enabled_providers: c.enabled_providers.includes(k) ? c.enabled_providers.filter((x: string) => x !== k) : [...c.enabled_providers, k] });
  return <><PageHeader title="Platform configuration" crumbs={[{ label: "Admin", href: "/admin" }, { label: "Configuration" }]} description={edit ? "Changes apply immediately and are audit-logged." : "Read-only: super admin required to change settings."} />
    <div className="max-w-2xl space-y-4">
      <Card><CardHeader><CardTitle>Access</CardTitle></CardHeader><CardContent className="space-y-4">
        <div className="flex items-center justify-between"><div><p className="text-sm font-medium">Open registration</p><p className="text-xs text-muted-foreground">Allow new accounts to sign up.</p></div><Switch checked={c.registration_open} disabled={!edit} onCheckedChange={(v) => save({ registration_open: v })} aria-label="Open registration" /></div>
        <div className="flex items-center justify-between"><div><p className="text-sm font-medium text-warning">Maintenance mode</p><p className="text-xs text-muted-foreground">Blocks the user API (503). Admin and sign-in remain available.</p></div><Switch checked={c.maintenance_mode} disabled={!edit} onCheckedChange={(v) => save({ maintenance_mode: v }, v ? "Maintenance mode ON" : "Maintenance mode OFF")} aria-label="Maintenance mode" /></div></CardContent></Card>
      <Card><CardHeader><CardTitle>Limits</CardTitle></CardHeader><CardContent><form className="flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); const v = Number((e.currentTarget.elements.namedItem("mcj") as HTMLInputElement).value); save({ max_concurrent_jobs: v }); }}><div className="flex-1"><Field label="Maximum concurrent assessment jobs (platform-wide)"><Input name="mcj" type="number" min={1} max={500} defaultValue={c.max_concurrent_jobs} disabled={!edit} /></Field></div>{edit && <Button type="submit">Save</Button>}</form><p className="mt-2 text-xs text-muted-foreground">Per-plan quotas are defined in the backend entitlement table.</p></CardContent></Card>
      <Card><CardHeader><CardTitle>Supported AI providers</CardTitle></CardHeader><CardContent className="space-y-3">{PROVIDERS.map(([k, l]) => <div key={k} className="flex items-center justify-between"><span className="text-sm">{l}</span><Switch checked={c.enabled_providers.includes(k)} disabled={!edit} onCheckedChange={() => toggleProvider(k)} aria-label={l} /></div>)}</CardContent></Card>
      <Card><CardHeader><CardTitle>Feature availability</CardTitle></CardHeader><CardContent className="space-y-3">{FEATURES.map(([k, l]) => <div key={k} className="flex items-center justify-between"><span className="text-sm">{l}</span><Switch checked={c.features[k]} disabled={!edit} onCheckedChange={(v) => save({ features: { [k]: v } })} aria-label={l} /></div>)}</CardContent></Card>
      <Card><CardHeader><CardTitle>System announcement</CardTitle><CardDescription>Sent as an in-app notification to every active user.</CardDescription></CardHeader><CardContent className="space-y-3">{c.announcement?.active && <p className="rounded-md border p-2 text-xs">Current: [{c.announcement.level}] {c.announcement.text}</p>}
        <Textarea rows={2} maxLength={500} value={ann.text} onChange={(e) => setAnn({ ...ann, text: e.target.value })} disabled={!edit} placeholder="Scheduled maintenance tonight at 22:00 UTC…" aria-label="Announcement text" />
        <div className="flex gap-2"><Select className="w-36" value={ann.level} onChange={(e) => setAnn({ ...ann, level: e.target.value })} disabled={!edit}><option value="info">Info</option><option value="warning">Warning</option><option value="critical">Critical</option></Select>
          <Button disabled={!edit || !ann.text.trim()} onClick={async () => { try { await api("/admin/announcements", { method: "POST", body: { ...ann, active: true } }); toast.success("Announcement published"); setAnn({ text: "", level: "info" }); d.reload(); } catch (e) { toast.error((e as ApiError).message); } }}>Publish</Button>
          {c.announcement?.active && <Button variant="outline" disabled={!edit} onClick={async () => { await api("/admin/announcements", { method: "POST", body: { text: c.announcement.text, level: c.announcement.level, active: false } }); toast.success("Announcement cleared"); d.reload(); }}>Clear</Button>}</div></CardContent></Card></div></>;
}
