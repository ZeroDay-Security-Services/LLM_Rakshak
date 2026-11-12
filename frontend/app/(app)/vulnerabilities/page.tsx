"use client";
import Link from "next/link";
import { useState } from "react";
import { ArrowDown, ArrowUp, ShieldAlert } from "lucide-react";
import { Card, Input, Select, Table, Td, Th, Tr } from "@/components/ui/primitives";
import { EmptyState, PageHeader, Pagination, SeverityBadge, StatusBadge, TableSkeleton } from "@/components/shared";
import { useApi, useDebounced } from "@/lib/hooks";
import { CATEGORY_LABELS, fmtDay, pct } from "@/lib/utils";

export default function Vulns() {
  const [f, setF] = useState({ q: "", severity: "", status: "", triage: "", category: "" }); const [sort, setSort] = useState("detected_at"); const [order, setOrder] = useState("desc"); const [page, setPage] = useState(1);
  const dq = useDebounced(f.q); const d = useApi<any>("/vulnerabilities", { ...f, q: dq, sort, order, page, size: 15 });
  const set = (k: string) => (e: React.ChangeEvent<any>) => { setF({ ...f, [k]: e.target.value }); setPage(1); };
  const head = (key: string, label: string) => <Th><button className="inline-flex items-center gap-1 hover:text-foreground" onClick={() => { if (sort === key) setOrder(order === "asc" ? "desc" : "asc"); else { setSort(key); setOrder("desc"); } }} aria-label={`Sort by ${label}`}>{label}{sort === key && (order === "asc" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />)}</button></Th>;
  return <><PageHeader title="Vulnerabilities" crumbs={[{ label: "Dashboard", href: "/dashboard" }, { label: "Vulnerabilities" }]} description="Every confirmed or suspected weakness found across your assessments." />
    <div className="mb-3 flex flex-wrap gap-2"><Input className="max-w-xs" placeholder="Search title or finding ID…" value={f.q} onChange={set("q")} aria-label="Search findings" />
      <Select className="w-36" value={f.severity} onChange={set("severity")} aria-label="Severity"><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</Select>
      <Select className="w-36" value={f.status} onChange={set("status")} aria-label="Workflow status"><option value="">All statuses</option>{["new", "confirmed", "in_progress", "fixed", "retested", "closed"].map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}</Select>
      <Select className="w-40" value={f.triage} onChange={set("triage")} aria-label="Triage"><option value="">All triage</option>{["unreviewed", "confirmed", "false_positive", "needs_review", "accepted_risk", "fixed"].map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}</Select>
      <Select className="w-48" value={f.category} onChange={set("category")} aria-label="Category"><option value="">All categories</option>{Object.entries(CATEGORY_LABELS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</Select></div>
    <Card>{!d.data ? <TableSkeleton /> : !d.data.items.length ? <EmptyState icon={ShieldAlert} title="No vulnerabilities" description="Findings appear here when an assessment detects a weakness." /> :
      <Table><thead><tr className="border-b">{head("title", "Finding")}{head("severity", "Severity")}<Th>Category</Th>{head("confidence", "Confidence")}<Th>Status</Th><Th>Model</Th>{head("detected_at", "Detected")}</tr></thead><tbody>
        {d.data.items.map((v: any) => <Tr key={v.id}><Td><Link href={`/vulnerabilities/${v.id}`} className="font-medium hover:text-primary">{v.title}</Link><p className="font-mono text-xs text-muted-foreground">{v.finding_id}</p></Td><Td><SeverityBadge severity={v.severity} /></Td><Td className="text-muted-foreground">{CATEGORY_LABELS[v.category]}</Td><Td className="tabular-nums">{pct(v.confidence)}</Td>
          <Td><div className="flex flex-wrap gap-1"><StatusBadge status={v.status} />{["needs_review", "false_positive", "accepted_risk"].includes(v.triage) && <StatusBadge status={v.triage} />}</div></Td><Td className="text-xs text-muted-foreground">{v.model}</Td><Td className="text-muted-foreground">{fmtDay(v.detected_at)}</Td></Tr>)}</tbody></Table>}
      {d.data && <div className="px-4 pb-3"><Pagination page={page} size={15} total={d.data.total} onPage={setPage} /></div>}</Card></>;
}
