import Link from "next/link";
import { ArrowRight, FileCheck2, Gauge, KeyRound, Network, ShieldCheck, Workflow } from "lucide-react";
import { Button, Card } from "@/components/ui/primitives";

const features = [
  { icon: Workflow, title: "Automated red-teaming", body: "84 original attack modules across prompt injection, jailbreaks, leakage, insecure output, agency, RAG, DoS, reliability, system prompt and tool abuse." },
  { icon: ShieldCheck, title: "Hybrid, evidence-based detection", body: "Deterministic canaries and rules first, behavioural checks next, Claude as a reviewer. Every finding stores its method, confidence and redacted evidence." },
  { icon: Gauge, title: "Transparent scoring", body: "A documented 0-100 score where confirmed evidence drives risk, unconfirmed behaviour is labelled, and untested areas are never presented as secure." },
  { icon: FileCheck2, title: "Client-ready reports", body: "PDF, HTML, JSON and CSV with methodology, scope, reproduction steps and prioritised remediation." },
  { icon: Network, title: "Any model, your keys", body: "Claude, OpenAI, Gemini, Hugging Face, OpenAI-compatible and self-hosted endpoints with encrypted BYOK credentials and SSRF-hardened connections." },
  { icon: KeyRound, title: "Built to be trusted", body: "Argon2id, rotating sessions, MFA, tenant isolation, tamper-evident audit logs and backend-enforced entitlements." },
];
export default function Home() {
  return <main>
    <section className="relative overflow-hidden"><div className="grid-bg pointer-events-none absolute inset-0" />
      <div className="relative mx-auto max-w-4xl px-4 py-24 text-center md:py-32">
        <p className="mx-auto mb-4 w-fit rounded-full border px-3 py-1 text-xs text-muted-foreground">AI security · LLM red-teaming · vulnerability assessment</p>
        <h1 className="text-4xl font-semibold tracking-tight md:text-6xl">Find LLM vulnerabilities <span className="text-primary">before attackers do.</span></h1>
        <p className="mx-auto mt-5 max-w-2xl text-balance text-muted-foreground md:text-lg">ZeroDay&apos;s LLM Rakshak runs bounded, authorised security assessments against your AI applications, shows what the evidence supports, scores your posture and tells you exactly how to fix it.</p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3"><Button size="lg" asChild><Link href="/register">Start free <ArrowRight className="h-4 w-4" /></Link></Button><Button size="lg" variant="outline" asChild><Link href="/docs">Read the docs</Link></Button></div>
      </div></section>
    <section className="mx-auto max-w-6xl px-4 pb-24"><div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">{features.map((f) => <Card key={f.title} className="p-5"><f.icon className="h-5 w-5 text-cyan" /><h3 className="mt-3 text-sm font-semibold">{f.title}</h3><p className="mt-1.5 text-sm text-muted-foreground">{f.body}</p></Card>)}</div></section>
    <section className="border-t"><div className="mx-auto max-w-3xl px-4 py-16 text-center"><h2 className="text-2xl font-semibold tracking-tight">Authorised testing only</h2><p className="mt-3 text-sm text-muted-foreground">Every assessment requires a documented authorisation. Requests are bounded, targets are SSRF-validated, secrets are redacted, and nothing runs unattended without limits.</p><Button className="mt-6" asChild><Link href="/pricing">View pricing</Link></Button></div></section>
  </main>;
}
