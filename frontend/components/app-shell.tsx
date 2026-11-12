"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import * as Dropdown from "@radix-ui/react-dropdown-menu";
import { Bell, Building2, ChevronsLeft, ChevronsRight, FileText, Gauge, KeyRound, LayoutDashboard, Library, LogOut, Menu, Moon, PlayCircle, Search, Settings, ShieldAlert, ShieldCheck, Sun, Users, Cpu, X, Activity, ScrollText, SlidersHorizontal, BarChart3 } from "lucide-react";
import { Logo } from "@/components/logo";
import { Button, Skeleton } from "@/components/ui/primitives";
import { SeverityBadge } from "@/components/shared";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import { useDebounced } from "@/lib/hooks";
import { cn } from "@/lib/utils";

type NavItem = { href: string; label: string; icon: any; perm?: string };
export const APP_NAV: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard }, { href: "/assessments", label: "Assessments", icon: PlayCircle }, { href: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
  { href: "/attacks", label: "Attack library", icon: Library }, { href: "/models", label: "Models", icon: Cpu }, { href: "/reports", label: "Reports", icon: FileText },
  { href: "/notifications", label: "Notifications", icon: Bell }, { href: "/organization", label: "Organization", icon: Building2 }, { href: "/settings", label: "Settings", icon: Settings },
];
export const ADMIN_NAV: NavItem[] = [
  { href: "/admin", label: "Overview", icon: Gauge }, { href: "/admin/users", label: "Users", icon: Users }, { href: "/admin/assessments", label: "Assessments", icon: PlayCircle },
  { href: "/admin/analytics", label: "Analytics", icon: BarChart3 }, { href: "/admin/health", label: "System health", icon: Activity }, { href: "/admin/audit", label: "Audit logs", icon: ScrollText }, { href: "/admin/config", label: "Configuration", icon: SlidersHorizontal },
];

function GlobalSearch() {
  const [q, setQ] = useState(""); const dq = useDebounced(q, 250); const [res, setRes] = useState<any>(null); const [open, setOpen] = useState(false); const ref = useRef<HTMLDivElement>(null); const router = useRouter();
  useEffect(() => {
    if (dq.trim().length < 2) { setRes(null); return; }
    let live = true;
    Promise.allSettled([api("/assessments", { params: { q: dq, size: 4 } }), api("/vulnerabilities", { params: { q: dq, size: 4 } }), api("/attacks", { params: { q: dq, size: 4 } })]).then(([a, v, k]) => {
      if (live) setRes({ a: a.status === "fulfilled" ? a.value.items : [], v: v.status === "fulfilled" ? v.value.items : [], k: k.status === "fulfilled" ? k.value.items : [] });
    });
    return () => { live = false; };
  }, [dq]);
  useEffect(() => { const h = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); }; document.addEventListener("mousedown", h); return () => document.removeEventListener("mousedown", h); }, []);
  const go = (href: string) => { setOpen(false); setQ(""); router.push(href); };
  const empty = res && !res.a.length && !res.v.length && !res.k.length;
  return <div ref={ref} className="relative w-full max-w-md">
    <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
    <input value={q} onChange={(e) => { setQ(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)} placeholder="Search assessments, findings, attacks…" aria-label="Global search" className="h-9 w-full rounded-md border bg-card pl-9 pr-3 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" />
    {open && res && <div className="absolute z-40 mt-1 max-h-96 w-full overflow-y-auto rounded-lg border bg-card p-1 shadow-xl">
      {empty && <p className="p-3 text-xs text-muted-foreground">No matches</p>}
      {res.a.length > 0 && <Group title="Assessments">{res.a.map((x: any) => <Row key={x.id} onClick={() => go(`/assessments/${x.id}`)} title={x.name} sub={x.status} />)}</Group>}
      {res.v.length > 0 && <Group title="Findings">{res.v.map((x: any) => <Row key={x.id} onClick={() => go(`/vulnerabilities/${x.id}`)} title={x.title} sub={x.finding_id} right={<SeverityBadge severity={x.severity} />} />)}</Group>}
      {res.k.length > 0 && <Group title="Attacks">{res.k.map((x: any) => <Row key={x.attack_id} onClick={() => go(`/attacks/${x.attack_id}`)} title={x.name} sub={x.attack_id} />)}</Group>}
    </div>}</div>;
}
const Group = ({ title, children }: { title: string; children: React.ReactNode }) => <div><p className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{title}</p>{children}</div>;
const Row = ({ title, sub, right, onClick }: { title: string; sub?: string; right?: React.ReactNode; onClick: () => void }) => <button onClick={onClick} className="flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left hover:bg-accent"><span className="min-w-0"><span className="block truncate text-sm">{title}</span><span className="block truncate text-xs text-muted-foreground">{sub}</span></span>{right}</button>;

function Bell_() {
  const [n, setN] = useState(0);
  useEffect(() => { let on = true; const f = () => api("/notifications/unread-count").then((d) => on && setN(d.count)).catch(() => {}); f(); const t = setInterval(f, 30000); return () => { on = false; clearInterval(t); }; }, []);
  return <Link href="/notifications" className="relative rounded-md p-2 hover:bg-accent" aria-label={`Notifications${n ? `, ${n} unread` : ""}`}><Bell className="h-4 w-4" />{n > 0 && <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-medium text-white">{n > 9 ? "9+" : n}</span>}</Link>;
}

export function AppShell({ children, admin = false }: { children: React.ReactNode; admin?: boolean }) {
  const { me, loading, can, logout } = useAuth();
  const path = usePathname(); const router = useRouter();
  const [collapsed, setCollapsed] = useState(false); const [mobile, setMobile] = useState(false);
  useEffect(() => { try { setCollapsed(localStorage.getItem("lg_sidebar") === "1"); } catch {} }, []);
  useEffect(() => setMobile(false), [path]);
  useEffect(() => { const t = me?.user.preferences?.theme; document.documentElement.classList.toggle("light", t === "light"); document.documentElement.classList.toggle("dark", t !== "light"); }, [me]);
  if (loading || !me) return <div className="flex min-h-screen"><Skeleton className="m-4 h-[calc(100vh-2rem)] w-56" /><div className="flex-1 space-y-4 p-6"><Skeleton className="h-9 w-72" /><Skeleton className="h-40" /><Skeleton className="h-64" /></div></div>;
  if (admin && !can("admin:access")) return <div className="flex min-h-screen flex-col items-center justify-center gap-3 text-center"><ShieldAlert className="h-8 w-8 text-danger" /><p className="font-medium">Administrator access required</p><Button variant="outline" onClick={() => router.push("/dashboard")}>Back to dashboard</Button></div>;
  const nav = admin ? ADMIN_NAV : APP_NAV;
  const toggle = () => { setCollapsed((c) => { try { localStorage.setItem("lg_sidebar", c ? "0" : "1"); } catch {} return !c; }); };
  const active = (h: string) => (h === "/admin" || h === "/dashboard" ? path === h : path.startsWith(h));
  const side = <nav className="flex h-full flex-col" aria-label="Main navigation">
    <div className={cn("flex h-14 items-center border-b px-4", collapsed && "justify-center px-0")}><Logo href={admin ? "/admin" : "/dashboard"} compact={collapsed} /></div>
    <ul className="flex-1 space-y-0.5 overflow-y-auto p-2">
      {admin && !collapsed && <li className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-warning">Administration</li>}
      {nav.map((n) => <li key={n.href}><Link href={n.href} title={n.label} aria-current={active(n.href) ? "page" : undefined} className={cn("flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors", active(n.href) ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent hover:text-foreground", collapsed && "justify-center px-0")}><n.icon className="h-4 w-4 shrink-0" />{!collapsed && n.label}</Link></li>)}
    </ul>
    <div className="border-t p-2 space-y-0.5">
      {can("admin:access") && <Link href={admin ? "/dashboard" : "/admin"} className={cn("flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground hover:bg-accent hover:text-foreground", collapsed && "justify-center px-0")} title={admin ? "User app" : "Admin"}><ShieldCheck className="h-4 w-4" />{!collapsed && (admin ? "User app" : "Admin panel")}</Link>}
      <button onClick={toggle} className="hidden w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground hover:bg-accent md:flex" aria-label="Toggle sidebar">{collapsed ? <ChevronsRight className="mx-auto h-4 w-4" /> : <><ChevronsLeft className="h-4 w-4" />Collapse</>}</button>
    </div></nav>;
  return <div className="min-h-screen">
    <aside className={cn("fixed inset-y-0 left-0 z-30 hidden border-r bg-card transition-all md:block", collapsed ? "w-16" : "w-60")}>{side}</aside>
    {mobile && <div className="fixed inset-0 z-40 md:hidden"><div className="absolute inset-0 bg-black/70" onClick={() => setMobile(false)} /><aside className="absolute inset-y-0 left-0 w-64 border-r bg-card">{side}</aside></div>}
    <div className={cn("transition-all", collapsed ? "md:pl-16" : "md:pl-60")}>
      <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur">
        <Button variant="ghost" size="icon" className="md:hidden" onClick={() => setMobile(true)} aria-label="Open menu"><Menu className="h-5 w-5" /></Button>
        <GlobalSearch /><div className="flex-1" />
        <span className="hidden rounded-md border px-2 py-1 text-xs text-muted-foreground sm:block">{me.plan.label}</span>
        <Bell_ />
        <Dropdown.Root><Dropdown.Trigger className="flex items-center gap-2 rounded-md p-1 hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring" aria-label="Account menu">
          <span className="flex h-7 w-7 items-center justify-center overflow-hidden rounded-full bg-primary/20 text-xs font-semibold text-primary">{me.user.has_avatar ? <img src="/api/profile/avatar" alt="" className="h-full w-full object-cover" /> : me.user.name.slice(0, 1).toUpperCase()}</span></Dropdown.Trigger>
          <Dropdown.Portal><Dropdown.Content align="end" sideOffset={8} className="z-50 w-56 rounded-lg border bg-card p-1 shadow-xl">
            <div className="px-2 py-2"><p className="truncate text-sm font-medium">{me.user.name}</p><p className="truncate text-xs text-muted-foreground">{me.user.email}</p><p className="mt-1 text-[10px] uppercase tracking-wide text-muted-foreground">{me.user.role.replace("_", " ")} · {me.organization.name}</p></div>
            <Dropdown.Separator className="my-1 h-px bg-border" />
            <Dropdown.Item onSelect={() => router.push("/settings")} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-accent"><Settings className="h-4 w-4" />Settings</Dropdown.Item>
            <Dropdown.Item onSelect={() => router.push("/settings?tab=api")} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-accent"><KeyRound className="h-4 w-4" />API keys</Dropdown.Item>
            <Dropdown.Separator className="my-1 h-px bg-border" />
            <Dropdown.Item onSelect={logout} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm text-danger outline-none data-[highlighted]:bg-accent"><LogOut className="h-4 w-4" />Sign out</Dropdown.Item>
          </Dropdown.Content></Dropdown.Portal></Dropdown.Root>
      </header>
      <main className="mx-auto max-w-7xl p-4 md:p-6">{children}</main>
    </div></div>;
}
