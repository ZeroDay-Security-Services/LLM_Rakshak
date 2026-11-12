"use client";
import { useState } from "react";
import { toast } from "sonner";
import { Cpu, Pencil, Plus, Trash2, Zap } from "lucide-react";
import { Button, Card, Dialog, DialogContent, Field, Input, Select, Table, Td, Textarea, Th, Tr } from "@/components/ui/primitives";
import { ConfirmDialog, EmptyState, ErrorNote, PageHeader, TableSkeleton } from "@/components/shared";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDay } from "@/lib/utils";

const blank = { name: "", provider: "anthropic", model: "", endpoint: "", system_prompt: "", temperature: "", max_tokens: 400 };
export default function Models() {
  const { can } = useAuth(); const d = useApi<any>("/models", { size: 100 }); const prov = useApi<any[]>("/providers"); const creds = useApi<any>("/credentials");
  const [open, setOpen] = useState(false); const [editId, setEditId] = useState<string | null>(null); const [f, setF] = useState<any>(blank); const [err, setErr] = useState<ApiError | null>(null); const [busy, setBusy] = useState(false);
  const [del, setDel] = useState<any>(null); const [testing, setTesting] = useState<string | null>(null);
  const p = prov.data?.find((x) => x.key === f.provider); const write = can("model:write");
  const edit = (m?: any) => { setErr(null); setEditId(m?.id ?? null); setF(m ? { name: m.name, provider: m.provider, model: m.model, endpoint: m.endpoint ?? "", system_prompt: m.system_prompt ?? "", temperature: m.params?.temperature ?? "", max_tokens: m.params?.max_tokens ?? 400 } : blank); setOpen(true); };
  async function save() {
    setBusy(true); setErr(null);
    try { const body = { name: f.name, provider: f.provider, model: f.model, endpoint: p?.needs_endpoint ? f.endpoint : undefined, system_prompt: f.system_prompt, params: { temperature: f.temperature === "" ? null : Number(f.temperature), max_tokens: Number(f.max_tokens) } };
      await api(editId ? `/models/${editId}` : "/models", { method: editId ? "PUT" : "POST", body }); toast.success(editId ? "Model updated" : "Model added"); setOpen(false); d.reload(); } catch (e) { setErr(e as ApiError); } finally { setBusy(false); }
  }
  async function test(id: string) { setTesting(id); try { const r = await api<any>(`/models/${id}/test`, { method: "POST" }); r.ok ? toast.success(`Connected · ${r.latency_ms} ms`) : toast.error(`Failed: ${r.status}${r.error ? ` – ${r.error}` : ""}`); } catch (e) { toast.error((e as ApiError).message); } finally { setTesting(null); } }
  return <><PageHeader title="Models" crumbs={[{ label: "Dashboard", href: "/dashboard" }, { label: "Models" }]} description="Target models and endpoints you are authorised to assess." actions={write && <Button onClick={() => edit()}><Plus className="h-4 w-4" />Add model</Button>} />
    <Card>{!d.data ? <TableSkeleton /> : !d.data.items.length ? <EmptyState icon={Cpu} title="No models configured" description="Add the model or endpoint you want to test. API keys are managed in Settings." action={write && <Button onClick={() => edit()}>Add model</Button>} /> :
      <Table><thead><tr className="border-b"><Th>Name</Th><Th>Provider</Th><Th>Model</Th><Th>Endpoint</Th><Th>Key</Th><Th>Added</Th><Th /></tr></thead><tbody>{d.data.items.map((m: any) => <Tr key={m.id}><Td className="font-medium">{m.name}</Td><Td className="text-muted-foreground">{m.provider}</Td><Td className="font-mono text-xs">{m.model}</Td><Td className="max-w-48 truncate text-xs text-muted-foreground">{m.endpoint ?? "—"}</Td>
        <Td className="text-xs">{creds.data?.[m.credential_provider] ? <span className="text-success">{creds.data[m.credential_provider].preview}</span> : <span className="text-warning">missing</span>}</Td><Td className="text-muted-foreground">{fmtDay(m.created_at)}</Td>
        <Td className="whitespace-nowrap text-right">{write && <><Button size="sm" variant="ghost" loading={testing === m.id} onClick={() => test(m.id)}><Zap className="h-3 w-3" />Test</Button><Button size="icon" variant="ghost" onClick={() => edit(m)} aria-label="Edit"><Pencil className="h-3 w-3" /></Button><Button size="icon" variant="ghost" onClick={() => setDel(m)} aria-label="Delete"><Trash2 className="h-3 w-3 text-danger" /></Button></>}</Td></Tr>)}</tbody></Table>}</Card>
    <Dialog open={open} onOpenChange={setOpen}><DialogContent title={editId ? "Edit model" : "Add model"} description="Credentials are taken from Settings → API configuration for the selected provider."><div className="space-y-3"><ErrorNote error={err} />
      <Field label="Display name"><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} maxLength={120} /></Field>
      <div className="grid grid-cols-2 gap-3"><Field label="Provider"><Select value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value, model: "" })}>{prov.data?.map((x) => <option key={x.key} value={x.key} disabled={!x.enabled}>{x.label}</option>)}</Select></Field><Field label="Model ID" hint={p?.default_model ? `e.g. ${p.default_model}` : undefined}><Input value={f.model} onChange={(e) => setF({ ...f, model: e.target.value })} placeholder={p?.default_model} /></Field></div>
      {p?.needs_endpoint && <Field label="Endpoint base URL" hint="HTTPS. Private, loopback and cloud-metadata addresses are rejected."><Input value={f.endpoint} onChange={(e) => setF({ ...f, endpoint: e.target.value })} placeholder="https://llm.example.com/v1" /></Field>}
      <Field label="System prompt (the target’s real prompt)" hint="Used for extraction-similarity checks. Never sent anywhere except to the target."><Textarea rows={3} maxLength={8000} value={f.system_prompt} onChange={(e) => setF({ ...f, system_prompt: e.target.value })} /></Field>
      <div className="grid grid-cols-2 gap-3"><Field label="Temperature (optional)"><Input type="number" step="0.1" min={0} max={2} value={f.temperature} onChange={(e) => setF({ ...f, temperature: e.target.value })} /></Field><Field label="Max output tokens"><Input type="number" min={16} max={1024} value={f.max_tokens} onChange={(e) => setF({ ...f, max_tokens: e.target.value })} /></Field></div>
      <div className="flex justify-end gap-2"><Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button><Button loading={busy} disabled={!f.name || !f.model} onClick={save}>{editId ? "Save" : "Add"}</Button></div></div></DialogContent></Dialog>
    <ConfirmDialog open={!!del} onOpenChange={(o) => !o && setDel(null)} title="Delete model?" description={`“${del?.name}” will be removed. Past assessments keep their results.`} destructive confirmLabel="Delete" onConfirm={async () => { try { await api(`/models/${del.id}`, { method: "DELETE" }); toast.success("Model deleted"); d.reload(); } catch (e) { toast.error((e as ApiError).message); } }} /></>;
}
