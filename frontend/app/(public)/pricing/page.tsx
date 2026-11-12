import Link from "next/link";
import { Check } from "lucide-react";
import { Button, Card } from "@/components/ui/primitives";
export const metadata = { title: "Pricing" };
const plans = [
  { name: "Free", price: "$0", sub: "", cta: "Start free", hl: false, feats: ["5 assessments / month", "Basic vulnerability modules", "HTML & JSON reports", "120 requests per assessment", "Basic analytics"] },
  { name: "Researcher", price: "$29", sub: "/ month", cta: "Get started", hl: true, feats: ["60 assessments / month", "Advanced attack modules", "PDF, HTML, JSON, CSV reports", "AI-assisted analysis (Claude)", "Custom attacks & import/export", "Extended analytics"] },
  { name: "Enterprise", price: "Custom", sub: "", cta: "Contact us", hl: false, feats: ["Organizations & team collaboration", "Up to 200 members, role-based access", "Higher usage limits", "Priority concurrency", "Custom integrations"] },
];
export default function Pricing() {
  return <main className="mx-auto max-w-5xl px-4 py-16"><h1 className="text-center text-3xl font-semibold tracking-tight">Simple, usage-based plans</h1><p className="mx-auto mt-3 max-w-xl text-center text-sm text-muted-foreground">You bring your own model API keys; provider usage is billed by your provider. Plan limits are enforced server-side.</p>
    <div className="mt-10 grid gap-4 md:grid-cols-3">{plans.map((p) => <Card key={p.name} className={p.hl ? "border-primary p-6" : "p-6"}><h3 className="text-sm font-semibold">{p.name}</h3><p className="mt-3 text-3xl font-semibold">{p.price}<span className="text-sm font-normal text-muted-foreground"> {p.sub}</span></p>
      <ul className="mt-5 space-y-2 text-sm">{p.feats.map((f) => <li key={f} className="flex gap-2"><Check className="mt-0.5 h-4 w-4 shrink-0 text-success" />{f}</li>)}</ul>
      <Button className="mt-6 w-full" variant={p.hl ? "default" : "outline"} asChild><Link href={p.name === "Enterprise" ? "mailto:sales@zeroday.example" : "/register"}>{p.cta}</Link></Button></Card>)}</div>
    <p className="mt-8 text-center text-xs text-muted-foreground">Paid plans are activated by the billing provider webhook or an administrator — never from the browser.</p></main>;
}
