export const metadata = { title: "Privacy Policy" };
export default function Privacy() {
  return <main className="prose-invert mx-auto max-w-3xl space-y-4 px-4 py-14 text-sm leading-relaxed text-muted-foreground"><h1 className="text-3xl font-semibold tracking-tight text-foreground">Privacy Policy</h1><p className="text-xs">Template – have it reviewed by counsel before launch.</p>
    {[["Data we collect", "Account data (name, email, organization), authentication metadata (IP address, device, login history), assessment configuration, redacted test evidence, findings, reports and usage metrics."],
      ["Credentials", "Provider API keys you add are encrypted at rest, are never returned by the API, never logged, and can be replaced or deleted at any time."],
      ["Evidence & redaction", "Responses from your models are redacted for credentials and personal data before storage. ZeroDay's LLM Rakshak plants synthetic canary values for leak detection and does not need your real secrets."],
      ["AI analysis", "If you enable AI-assisted analysis, redacted test transcripts are sent to Anthropic using your key or the platform key."],
      ["Retention & deletion", "Login history is kept for 180 days and notifications for 90 days. You can delete assessments, reports and credentials at any time; deleting an assessment removes its findings and reports."],
      ["Security", "Argon2id password hashing, TLS in transit, encryption of credentials, tenant isolation and tamper-evident audit logging."],
      ["Contact", "privacy@zeroday.example"]].map(([t, b]) => <section key={t}><h2 className="text-base font-semibold text-foreground">{t}</h2><p>{b}</p></section>)}</main>;
}
