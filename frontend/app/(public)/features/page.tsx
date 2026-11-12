import Link from "next/link";
import { Button, Card } from "@/components/ui/primitives";
export const metadata = { title: "Features" };
const cats = [
  ["Prompt injection", "Direct and indirect injection, fake system blocks, payload splitting, long-context burial, untrusted-field handling."], ["Jailbreak testing", "Persona, fiction, multi-turn, encoding (Base64/ROT13), spoofed history and authority claims against a forbidden-string policy."],
  ["Sensitive disclosure", "Confidential token, debug-dump, cross-user PII and credential-pattern leakage using planted synthetic secrets."], ["Insecure output", "Script/handler injection, Markdown exfiltration, javascript: links, SQL/command concatenation and JSON structure injection indicators."],
  ["Excessive agency", "Injected destructive tool calls, actions without approval, external data forwarding and privilege boundaries."], ["RAG security", "Poisoned chunks, conflicting facts, cross-tenant leakage, restricted-label exposure, self-declared authority."],
  ["Model DoS", "Bounded oversized and repeated inputs, output amplification and burst/rate-limit behaviour with strict budgets."], ["Hallucination & reliability", "Fabricated citations, invented APIs, fictional-entity stats, consistency and unsafe recommendations."],
  ["System prompt security", "Verbatim, paraphrase, translation, YAML and code-block extraction plus policy-boundary disclosure."], ["Tool & function calling", "Command execution from untrusted content, identifier tampering, privilege-claim escalation, argument injection, tool exfiltration."],
];
export default function Features() {
  return <main className="mx-auto max-w-6xl px-4 py-16"><h1 className="text-3xl font-semibold tracking-tight">Everything you need to assess an LLM application</h1><p className="mt-3 max-w-2xl text-muted-foreground">Ten security modules, mapped to OWASP LLM Top 10 (2025), CWE and MITRE ATLAS, with evidence and remediation for each.</p>
    <div className="mt-10 grid gap-4 md:grid-cols-2">{cats.map(([t, b]) => <Card key={t} className="p-5"><h3 className="text-sm font-semibold">{t}</h3><p className="mt-1.5 text-sm text-muted-foreground">{b}</p></Card>)}</div>
    <div className="mt-12 grid gap-4 md:grid-cols-3">{[["Hybrid analysis", "Deterministic rules, pattern matching, behavioural refusal analysis and optional Claude review. AI never overrides a strong deterministic hit."], ["Findings workflow", "New → Confirmed → In progress → Fixed → Retested → Closed, plus triage: confirmed, false positive, needs review, accepted risk."], ["Teams & SaaS", "Organizations, invitations, roles, quotas and plans enforced on the backend."]].map(([t, b]) => <Card key={t} className="p-5"><h3 className="text-sm font-semibold">{t}</h3><p className="mt-1.5 text-sm text-muted-foreground">{b}</p></Card>)}</div>
    <div className="mt-12 text-center"><Button asChild><Link href="/register">Start free</Link></Button></div></main>;
}
