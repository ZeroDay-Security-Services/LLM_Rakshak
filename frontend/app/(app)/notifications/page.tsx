"use client";
import Link from "next/link";
import { useState } from "react";
import { Bell, CheckCheck } from "lucide-react";
import { Button, Card } from "@/components/ui/primitives";
import { EmptyState, PageHeader, Pagination, TableSkeleton } from "@/components/shared";
import { api } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { cn, timeAgo } from "@/lib/utils";

export default function Notifications() {
  const [page, setPage] = useState(1); const [unread, setUnread] = useState(false); const d = useApi<any>("/notifications", { page, size: 20, unread: unread || undefined }, { poll: 20000 });
  return <><PageHeader title="Notifications" crumbs={[{ label: "Dashboard", href: "/dashboard" }, { label: "Notifications" }]} actions={<><Button variant={unread ? "secondary" : "outline"} size="sm" onClick={() => { setUnread(!unread); setPage(1); }}>{unread ? "Showing unread" : "Unread only"}</Button><Button variant="outline" size="sm" onClick={async () => { await api("/notifications/read-all", { method: "POST" }); d.reload(); }}><CheckCheck className="h-3 w-3" />Mark all read</Button></>} />
    <Card>{!d.data ? <TableSkeleton /> : !d.data.items.length ? <EmptyState icon={Bell} title="You’re all caught up" description="Assessment results, critical findings and account alerts will appear here." /> :
      <ul className="divide-y">{d.data.items.map((n: any) => { const inner = <><div className="flex items-start gap-3"><span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", n.read ? "bg-transparent" : "bg-primary")} /><div className="min-w-0"><p className={cn("text-sm", n.read ? "text-muted-foreground" : "font-medium")}>{n.title}</p><p className="mt-0.5 break-words text-xs text-muted-foreground">{n.body}</p></div></div><span className="shrink-0 text-xs text-muted-foreground">{timeAgo(n.created_at)}</span></>;
        const click = async () => { if (!n.read) { await api(`/notifications/${n.id}/read`, { method: "POST" }); d.reload(); } };
        return <li key={n.id}>{n.link ? <Link href={n.link} onClick={click} className="flex items-start justify-between gap-3 px-4 py-3 hover:bg-accent/40">{inner}</Link> : <button onClick={click} className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left hover:bg-accent/40">{inner}</button>}</li>; })}</ul>}
      {d.data && <div className="px-4 pb-3"><Pagination page={page} size={20} total={d.data.total} onPage={setPage} /></div>}</Card></>;
}
