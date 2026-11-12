"use client";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { Download, FileText, Trash2 } from "lucide-react";
import { Button, Card, Table, Td, Th, Tr } from "@/components/ui/primitives";
import { ConfirmDialog, EmptyState, PageHeader, Pagination, TableSkeleton } from "@/components/shared";
import { api, download } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useAuth } from "@/lib/auth";
import { fmtDate } from "@/lib/utils";

export default function Reports() {
  const [page, setPage] = useState(1); const d = useApi<any>("/reports", { page, size: 15 }); const { can } = useAuth(); const [del, setDel] = useState<any>(null);
  return <><PageHeader title="Reports" crumbs={[{ label: "Dashboard", href: "/dashboard" }, { label: "Reports" }]} description="Generated assessment reports. Create new ones from an assessment’s Reports tab." />
    <Card>{!d.data ? <TableSkeleton /> : !d.data.items.length ? <EmptyState icon={FileText} title="No reports yet" description="Open a finished assessment and generate a PDF, HTML, JSON or CSV report." action={<Button asChild variant="outline"><Link href="/assessments">Go to assessments</Link></Button>} /> :
      <Table><thead><tr className="border-b"><Th>Report</Th><Th>Assessment</Th><Th>Format</Th><Th>Version</Th><Th>Size</Th><Th>Generated</Th><Th /></tr></thead><tbody>{d.data.items.map((r: any) => <Tr key={r.id}><Td className="font-mono text-xs">{r.report_id}</Td><Td><Link href={`/assessments/${r.assessment_id}`} className="hover:text-primary">{r.name}</Link></Td><Td className="uppercase">{r.format}</Td><Td>v{r.version}</Td><Td className="text-muted-foreground">{(r.size / 1024).toFixed(0)} KB</Td><Td className="text-muted-foreground">{fmtDate(r.created_at)}</Td>
        <Td className="whitespace-nowrap text-right"><Button size="sm" variant="outline" onClick={() => download(`/reports/${r.id}/download`).catch(() => toast.error("Download failed"))}><Download className="h-3 w-3" />Download</Button>{can("report:write") && <Button size="icon" variant="ghost" onClick={() => setDel(r)} aria-label="Delete report"><Trash2 className="h-3 w-3 text-danger" /></Button>}</Td></Tr>)}</tbody></Table>}
      {d.data && <div className="px-4 pb-3"><Pagination page={page} size={15} total={d.data.total} onPage={setPage} /></div>}</Card>
    <ConfirmDialog open={!!del} onOpenChange={(o) => !o && setDel(null)} title="Delete report?" description={`${del?.report_id} will be permanently deleted.`} destructive confirmLabel="Delete" onConfirm={async () => { await api(`/reports/${del.id}`, { method: "DELETE" }); toast.success("Deleted"); d.reload(); }} /></>;
}
