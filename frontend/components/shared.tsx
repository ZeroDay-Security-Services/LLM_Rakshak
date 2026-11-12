"use client";
import Link from "next/link";
import { ChevronLeft, ChevronRight, ChevronRight as Sep, Inbox } from "lucide-react";
import { Button, Card, Dialog, DialogContent, DialogClose } from "@/components/ui/primitives";
import { cn, SEV_COLOR } from "@/lib/utils";
import { useState } from "react";

export function PageHeader({ title, description, crumbs = [], actions }: { title: string; description?: string; crumbs?: { label: string; href?: string }[]; actions?: React.ReactNode }) {
  return <div className="mb-6 space-y-2">
    {crumbs.length > 0 && <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-xs text-muted-foreground">
      {crumbs.map((c, i) => <span key={i} className="flex items-center gap-1">{i > 0 && <Sep className="h-3 w-3" />}{c.href ? <Link href={c.href} className="hover:text-foreground">{c.label}</Link> : <span aria-current="page" className="text-foreground">{c.label}</span>}</span>)}
    </nav>}
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h1 className="text-xl font-semibold tracking-tight">{title}</h1>{description && <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p>}</div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div></div>;
}

export function EmptyState({ icon: Icon = Inbox, title, description, action }: { icon?: any; title: string; description?: string; action?: React.ReactNode }) {
  return <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed py-14 text-center">
    <div className="rounded-full bg-accent p-3"><Icon className="h-5 w-5 text-muted-foreground" /></div>
    <div><p className="text-sm font-medium">{title}</p>{description && <p className="mx-auto mt-1 max-w-sm text-xs text-muted-foreground">{description}</p>}</div>{action}</div>;
}

export function StatCard({ label, value, hint, icon: Icon, tone }: { label: string; value: React.ReactNode; hint?: string; icon?: any; tone?: string }) {
  return <Card className="p-4"><div className="flex items-center justify-between"><p className="text-xs text-muted-foreground">{label}</p>{Icon && <Icon className="h-4 w-4 text-muted-foreground" />}</div>
    <p className={cn("mt-2 text-2xl font-semibold tabular-nums", tone)}>{value}</p>{hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}</Card>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className="inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium capitalize" style={{ borderColor: SEV_COLOR[severity] + "55", color: SEV_COLOR[severity], background: SEV_COLOR[severity] + "14" }}>
    <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLOR[severity] }} />{severity === "info" ? "informational" : severity}</span>;
}

const STATUS_TONE: Record<string, string> = {
  completed: "text-success border-success/30 bg-success/10", passed: "text-success border-success/30 bg-success/10", closed: "text-success border-success/30 bg-success/10", retested: "text-success border-success/30 bg-success/10", fixed: "text-success border-success/30 bg-success/10",
  running: "text-primary border-primary/30 bg-primary/10", queued: "text-cyan border-cyan/30 bg-cyan/10", in_progress: "text-primary border-primary/30 bg-primary/10", pausing: "text-warning border-warning/30 bg-warning/10", cancelling: "text-warning border-warning/30 bg-warning/10",
  failed: "text-danger border-danger/30 bg-danger/10", error: "text-danger border-danger/30 bg-danger/10", cancelled: "text-muted-foreground border-border bg-muted",
  paused: "text-warning border-warning/30 bg-warning/10", inconclusive: "text-warning border-warning/30 bg-warning/10", needs_review: "text-warning border-warning/30 bg-warning/10", new: "text-cyan border-cyan/30 bg-cyan/10", confirmed: "text-danger border-danger/30 bg-danger/10",
};
export function StatusBadge({ status }: { status: string }) {
  const label = status === "skipped" ? "not tested" : status.replace(/_/g, " ");
  return <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize", STATUS_TONE[status] ?? "text-muted-foreground border-border bg-muted")}>{label}</span>;
}

export function Pagination({ page, size, total, onPage }: { page: number; size: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size));
  return <div className="flex items-center justify-between pt-3 text-xs text-muted-foreground">
    <span>{total === 0 ? "No results" : `${(page - 1) * size + 1}–${Math.min(page * size, total)} of ${total}`}</span>
    <div className="flex items-center gap-1">
      <Button variant="outline" size="icon" className="h-7 w-7" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page"><ChevronLeft className="h-4 w-4" /></Button>
      <span className="px-2">Page {page} / {pages}</span>
      <Button variant="outline" size="icon" className="h-7 w-7" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page"><ChevronRight className="h-4 w-4" /></Button>
    </div></div>;
}

export function ConfirmDialog({ open, onOpenChange, title, description, confirmLabel = "Confirm", destructive, onConfirm }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; description: string; confirmLabel?: string; destructive?: boolean; onConfirm: () => Promise<void> | void }) {
  const [busy, setBusy] = useState(false);
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent title={title} description={description}>
    <div className="flex justify-end gap-2"><DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
      <Button variant={destructive ? "destructive" : "default"} loading={busy} onClick={async () => { setBusy(true); try { await onConfirm(); onOpenChange(false); } finally { setBusy(false); } }}>{confirmLabel}</Button></div>
  </DialogContent></Dialog>;
}

export function ScoreRing({ score, size = 120, label }: { score: number | null | undefined; size?: number; label?: string }) {
  const r = size / 2 - 8, c = 2 * Math.PI * r, v = score ?? 0;
  const color = score == null ? "hsl(var(--muted-foreground))" : score >= 90 ? "hsl(var(--success))" : score >= 75 ? "hsl(var(--cyan))" : score >= 60 ? "hsl(var(--warning))" : "hsl(var(--danger))";
  return <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }} role="img" aria-label={`Security score ${score ?? "not assessed"}`}>
    <svg width={size} height={size} className="-rotate-90"><circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="hsl(var(--secondary))" strokeWidth="8" />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c - (c * v) / 100} style={{ transition: "stroke-dashoffset .8s" }} /></svg>
    <div className="absolute text-center"><div className="text-2xl font-semibold tabular-nums" style={{ color }}>{score ?? "N/A"}</div>{label && <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>}</div></div>;
}

export function ErrorNote({ error }: { error: { message: string } | null }) {
  return error ? <div role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">{error.message}</div> : null;
}

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return <div className="space-y-2 p-4">{Array.from({ length: rows }).map((_, i) => <div key={i} className="h-9 animate-pulse rounded-md bg-accent/50" />)}</div>;
}
