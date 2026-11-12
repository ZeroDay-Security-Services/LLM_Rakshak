"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Plus, PlayCircle } from "lucide-react";
import { Button, Card, Input, Select, Table, Td, Th, Tr } from "@/components/ui/primitives";
import { EmptyState, PageHeader, Pagination, StatusBadge, TableSkeleton } from "@/components/shared";
import { useApi, useDebounced } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate, scoreColor } from "@/lib/utils";

export default function Assessments() {
  const [q, setQ] = useState(""); const [status, setStatus] = useState(""); const [page, setPage] = useState(1); const dq = useDebounced(q); const router = useRouter(); const { can } = useAuth();
  const { data, loading } = useApi<any>("/assessments", { q: dq, status, page, size: 15 }, { poll: 5000 });
  return <><PageHeader title="Assessments" crumbs={[{ label: "Dashboard", href: "/dashboard" }, { label: "Assessments" }]} description="Configure, run and review security assessments." actions={can("assessment:write") && <Button asChild><Link href="/assessments/new"><Plus className="h-4 w-4" />New assessment</Link></Button>} />
    <div className="mb-3 flex flex-wrap gap-2"><Input placeholder="Search by name…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} className="max-w-xs" aria-label="Search assessments" />
      <Select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} className="w-40" aria-label="Filter by status"><option value="">All statuses</option>{["draft", "queued", "running", "paused", "completed", "failed", "cancelled"].map((s) => <option key={s} value={s}>{s}</option>)}</Select></div>
    <Card>{loading && !data ? <TableSkeleton /> : !data?.items.length ? <EmptyState icon={PlayCircle} title="No assessments found" description={q || status ? "Try different filters." : "Create your first assessment to start testing a model."} action={can("assessment:write") && <Button asChild><Link href="/assessments/new">New assessment</Link></Button>} /> :
      <Table><thead><tr className="border-b"><Th>Name</Th><Th>Target</Th><Th>Status</Th><Th>Score</Th><Th>Findings</Th><Th>Created</Th></tr></thead><tbody>
        {data.items.map((a: any) => <Tr key={a.id} className="cursor-pointer" onClick={() => router.push(`/assessments/${a.id}`)}><Td><Link href={`/assessments/${a.id}`} className="font-medium hover:text-primary">{a.name}</Link></Td><Td className="text-muted-foreground">{a.provider}/{a.model_name}</Td><Td><StatusBadge status={a.status} /></Td>
          <Td className={`tabular-nums font-semibold ${scoreColor(a.score?.overall)}`}>{a.score?.overall ?? "—"}{a.score?.provisional && <span className="ml-1 text-[10px] font-normal text-warning">prov.</span>}</Td><Td className="tabular-nums">{a.score ? a.score.failed : "—"}</Td><Td className="text-muted-foreground">{fmtDate(a.created_at)}</Td></Tr>)}</tbody></Table>}
      {data && <div className="px-4 pb-3"><Pagination page={page} size={15} total={data.total} onPage={setPage} /></div>}</Card></>;
}
