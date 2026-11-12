import Link from "next/link";
import { Logo } from "@/components/logo";
import { Button } from "@/components/ui/primitives";
const links = [["/features", "Features"], ["/docs", "Documentation"], ["/pricing", "Pricing"]];
export default function PublicLayout({ children }: { children: React.ReactNode }) {
  return <div className="min-h-screen">
    <header className="sticky top-0 z-30 border-b bg-background/80 backdrop-blur"><div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4"><Logo />
      <nav className="hidden items-center gap-6 text-sm text-muted-foreground md:flex" aria-label="Primary">{links.map(([h, l]) => <Link key={h} href={h} className="hover:text-foreground">{l}</Link>)}</nav>
      <div className="flex items-center gap-2"><Button variant="ghost" size="sm" asChild><Link href="/login">Sign in</Link></Button><Button size="sm" asChild><Link href="/register">Get started</Link></Button></div></div></header>
    {children}
    <footer className="border-t"><div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-4 py-8 text-xs text-muted-foreground sm:flex-row"><span>© {new Date().getFullYear()} ZeroDay Security Services. ZeroDay&apos;s LLM Rakshak. Test only systems you own or are authorised to assess.</span>
      <div className="flex gap-4"><Link href="/privacy" className="hover:text-foreground">Privacy</Link><Link href="/terms" className="hover:text-foreground">Terms</Link><Link href="/docs" className="hover:text-foreground">Docs</Link></div></div></footer></div>;
}
