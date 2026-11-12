"use client";
import { useState } from "react";
import { toast } from "sonner";
import { ShieldCheck } from "lucide-react";
import { Button, Card, Input, Table, Td, Th, Tr } from "@/components/ui/primitives";
import { PageHeader, Pagination, TableSkeleton } from "@/components/shared";
import { api } from "@/lib/api";
import { useApi, useDebounced } from "@/lib/hooks";
import { fmtDate } from "@/lib/utils";

export default function Audit() {
  const [action, setAction] = useState(""); const [actor, setActor] = useState(""); const [page, setPage] = useState(1); const da = useDebounced(action); const dr = useDebounced(actor);
  const d = useApi<any>("/admin/audit", { action: da, actor: dr, page, size: 50 }); const [busy, setBusy] = useState(false);
  async function verify() { setBusy(true); try { const r = await api<any>("/admin/audit/verify"); r.ok ? toast.success(`Chain intact · ${r.checked} entries verified`) : toast.error(`Chain broken at entry #${r.broken_at_seq}`); } finally { setBusy(false); } }
  return <><PageHeader title="Audit logs" crumbs={[{ label: "Admin", href: "/admin" }, { label: "Audit logs" }]} description="Append-only, hash-chained records of authentication, administrative, lifecycle and configuration events." actions={<Button variant="outline" loading={busy} onClick={verify}><ShieldCheck className="h-4 w-4" />Verify integrity</Button>} />
    <div className="mb-3 flex flex-wrap gap-2"><Input className="max-w-xs" placeholder="Action prefix (e.g. auth., admin.)" value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} aria-label="Filter by action" /><Input className="max-w-xs" placeholder="Actor email or ID" value={actor} onChange={(e) => { setActor(e.target.value); setPage(1); }} aria-label="Filter by actor" /></div>
    <Card>{!d.data ? <TableSkeleton rows={10} /> : <Table><thead><tr className="border-b"><Th>#</Th><Th>Time</Th><Th>Action</Th><Th>Actor</Th><Th>Target</Th><Th>IP</Th><Th>Details</Th></tr></thead><tbody>{d.data.items.map((a: any) => <Tr key={a.seq}><Td className="tabular-nums text-muted-foreground">{a.seq}</Td><Td className="whitespace-nowrap text-muted-foreground">{fmtDate(a.ts)}</Td><Td className="font-mono text-xs">{a.action}</Td><Td className="text-xs">{a.actor_email ?? a.actor_id ?? "system"}</Td><Td className="max-w-40 truncate font-mono text-xs text-muted-foreground">{a.target ?? "—"}</Td><Td className="text-xs text-muted-foreground">{a.ip ?? "—"}</Td><Td className="max-w-64 truncate font-mono text-[11px] text-muted-foreground" title={JSON.stringify(a.meta)}>{Object.keys(a.meta ?? {}).length ? JSON.stringify(a.meta) : ""}</Td></Tr>)}</tbody></Table>}
      {d.data && <div className="px-4 pb-3"><Pagination page={page} size={50} total={d.data.total} onPage={setPage} /></div>}</Card></>;
}
