"use client";
import { useState } from "react";
import { Card, Select, Table, Td, Th, Tr } from "@/components/ui/primitives";
import { PageHeader, Pagination, StatusBadge, TableSkeleton } from "@/components/shared";
import { useApi } from "@/lib/hooks";
import { fmtDate } from "@/lib/utils";

export default function AdminAssessments() {
  const [status, setStatus] = useState(""); const [page, setPage] = useState(1); const d = useApi<any>("/admin/assessments", { status, page, size: 25 }, { poll: 5000 });
  return <><PageHeader title="Assessment monitoring" crumbs={[{ label: "Admin", href: "/admin" }, { label: "Assessments" }]} description="Live view across all tenants (configuration and evidence are not exposed)." />
    <Select className="mb-3 w-44" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Status"><option value="">All (excluding drafts)</option>{["queued", "running", "pausing", "paused", "completed", "failed", "cancelled"].map((s) => <option key={s}>{s}</option>)}</Select>
    <Card>{!d.data ? <TableSkeleton /> : <Table><thead><tr className="border-b"><Th>Name</Th><Th>Target</Th><Th>Status</Th><Th>Requests</Th><Th>Created</Th><Th>Heartbeat</Th></tr></thead><tbody>{d.data.items.map((a: any) => <Tr key={a.id}><Td className="font-medium">{a.name}</Td><Td className="text-muted-foreground">{a.provider}/{a.model_name}</Td><Td><StatusBadge status={a.status} />{a.error && <p className="mt-0.5 max-w-xs truncate text-[10px] text-danger">{a.error}</p>}</Td><Td className="tabular-nums">{a.usage?.requests ?? 0}</Td><Td className="text-muted-foreground">{fmtDate(a.created_at)}</Td><Td className="text-muted-foreground">{a.heartbeat_at ? fmtDate(a.heartbeat_at) : "—"}</Td></Tr>)}</tbody></Table>}
      {d.data && <div className="px-4 pb-3"><Pagination page={page} size={25} total={d.data.total} onPage={setPage} /></div>}</Card></>;
}
