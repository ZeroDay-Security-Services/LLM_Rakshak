"use client";
import { useState } from "react";
import { toast } from "sonner";
import { Button, Card, Dialog, DialogContent, Input, Select, Skeleton, Table, Td, Th, Tr } from "@/components/ui/primitives";
import { ConfirmDialog, PageHeader, Pagination, StatusBadge, TableSkeleton } from "@/components/shared";
import { api, ApiError } from "@/lib/api";
import { useApi, useDebounced } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, fmtDay } from "@/lib/utils";

const ROLES = ["super_admin", "admin", "researcher", "user", "viewer"];
export default function AdminUsers() {
  const { can, me } = useAuth(); const [q, setQ] = useState(""); const [role, setRole] = useState(""); const [active, setActive] = useState(""); const [page, setPage] = useState(1); const dq = useDebounced(q);
  const d = useApi<any>("/admin/users", { q: dq, role, active, page, size: 20 }); const [sel, setSel] = useState<string | null>(null); const [confirm, setConfirm] = useState<any>(null);
  const detail = useApi<any>(sel ? `/admin/users/${sel}` : null);
  const patch = async (id: string, body: any, ok: string) => { try { await api(`/admin/users/${id}`, { method: "PATCH", body }); toast.success(ok); d.reload(); detail.reload(); } catch (e) { toast.error((e as ApiError).message); } };
  return <><PageHeader title="Users" crumbs={[{ label: "Admin", href: "/admin" }, { label: "Users" }]} description="Search, review and manage accounts. Every change is audit-logged." />
    <div className="mb-3 flex flex-wrap gap-2"><Input className="max-w-xs" placeholder="Search name or email…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} aria-label="Search users" />
      <Select className="w-40" value={role} onChange={(e) => { setRole(e.target.value); setPage(1); }} aria-label="Role"><option value="">All roles</option>{ROLES.map((r) => <option key={r} value={r}>{r.replace("_", " ")}</option>)}</Select>
      <Select className="w-36" value={active} onChange={(e) => { setActive(e.target.value); setPage(1); }} aria-label="Account state"><option value="">All accounts</option><option value="true">Active</option><option value="false">Suspended</option></Select></div>
    <Card>{!d.data ? <TableSkeleton /> : <Table><thead><tr className="border-b"><Th>User</Th><Th>Role</Th><Th>State</Th><Th>Verified</Th><Th>MFA</Th><Th>Joined</Th><Th /></tr></thead><tbody>{d.data.items.map((u: any) => <Tr key={u.id}><Td><p className="font-medium">{u.name}</p><p className="text-xs text-muted-foreground">{u.email}</p></Td>
      <Td>{can("admin:roles") && u.id !== me!.user.id ? <Select className="h-8 w-32 text-xs" value={u.role} onChange={(e) => setConfirm({ u, body: { role: e.target.value }, title: "Change role?", desc: `${u.email} → ${e.target.value.replace("_", " ")}. Their sessions will be revoked.` })} aria-label={`Role for ${u.email}`}>{ROLES.map((r) => <option key={r} value={r}>{r.replace("_", " ")}</option>)}</Select> : <span className="capitalize">{u.role.replace("_", " ")}</span>}</Td>
      <Td><StatusBadge status={u.is_active ? "completed" : "failed"} /><span className="sr-only">{u.is_active ? "active" : "suspended"}</span><span className="ml-1 text-xs text-muted-foreground">{u.is_active ? "active" : "suspended"}</span></Td><Td>{u.email_verified ? "yes" : "no"}</Td><Td>{u.mfa_enabled ? "yes" : "no"}</Td><Td className="text-muted-foreground">{fmtDay(u.created_at)}</Td>
      <Td className="whitespace-nowrap text-right"><Button size="sm" variant="ghost" onClick={() => setSel(u.id)}>Details</Button>{u.id !== me!.user.id && <Button size="sm" variant={u.is_active ? "outline" : "default"} onClick={() => setConfirm({ u, body: { is_active: !u.is_active }, title: u.is_active ? "Suspend account?" : "Activate account?", desc: `${u.email} ${u.is_active ? "will be signed out and unable to log in" : "will regain access"}.` })}>{u.is_active ? "Suspend" : "Activate"}</Button>}</Td></Tr>)}</tbody></Table>}
      {d.data && <div className="px-4 pb-3"><Pagination page={page} size={20} total={d.data.total} onPage={setPage} /></div>}</Card>
    <ConfirmDialog open={!!confirm} onOpenChange={(o) => !o && setConfirm(null)} title={confirm?.title ?? ""} description={confirm?.desc ?? ""} onConfirm={() => patch(confirm.u.id, confirm.body, "Updated")} />
    <Dialog open={!!sel} onOpenChange={(o) => !o && setSel(null)}><DialogContent title="User details" className="max-w-2xl">{!detail.data ? <Skeleton className="h-40" /> : <div className="space-y-4 text-sm"><div className="grid grid-cols-2 gap-2"><div><p className="text-xs text-muted-foreground">Name</p>{detail.data.user.name}</div><div><p className="text-xs text-muted-foreground">Email</p>{detail.data.user.email}</div><div><p className="text-xs text-muted-foreground">Plan</p><span className="capitalize">{detail.data.plan ?? "—"}</span></div><div><p className="text-xs text-muted-foreground">Assessments (total / this month)</p>{detail.data.assessments} / {detail.data.usage?.assessments ?? 0}</div><div><p className="text-xs text-muted-foreground">Last login</p>{fmtDate(detail.data.user.last_login_at)}</div><div><p className="text-xs text-muted-foreground">Organization</p>{detail.data.user.organization ?? "—"}</div></div>
      <div><p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Recent account activity</p><ul className="max-h-40 overflow-auto text-xs">{detail.data.activity.map((a: any) => <li key={a.seq} className="flex justify-between border-b py-1"><span>{a.action}</span><span className="text-muted-foreground">{fmtDate(a.ts)}</span></li>)}{!detail.data.activity.length && <li className="text-muted-foreground">No audited actions.</li>}</ul></div>
      <div><p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Sign-ins</p><ul className="max-h-32 overflow-auto text-xs">{detail.data.logins.map((l: any) => <li key={l.id} className="flex justify-between border-b py-1"><span className={l.success ? "" : "text-danger"}>{l.success ? "success" : l.reason}</span><span className="text-muted-foreground">{l.ip} · {fmtDate(l.ts)}</span></li>)}</ul></div>
      {can("admin:billing") && <PlanSetter id={detail.data.user.id} onDone={() => detail.reload()} />}</div>}</DialogContent></Dialog></>;
}
function PlanSetter({ id, onDone }: { id: string; onDone: () => void }) {
  const [plan, setPlan] = useState("free");
  return <div className="flex items-end gap-2 border-t pt-3"><div className="flex-1"><p className="mb-1 text-xs text-muted-foreground">Set plan (manual entitlement)</p><Select value={plan} onChange={(e) => setPlan(e.target.value)}><option value="free">Free</option><option value="researcher">Researcher</option><option value="enterprise">Enterprise</option></Select></div>
    <Button variant="outline" onClick={async () => { try { await api(`/admin/users/${id}/plan`, { method: "PUT", body: { plan } }); toast.success("Plan updated"); onDone(); } catch (e) { toast.error((e as ApiError).message); } }}>Apply</Button></div>;
}
