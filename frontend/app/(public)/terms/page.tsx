export const metadata = { title: "Terms of Service" };
export default function Terms() {
  return <main className="mx-auto max-w-3xl space-y-4 px-4 py-14 text-sm leading-relaxed text-muted-foreground"><h1 className="text-3xl font-semibold tracking-tight text-foreground">Terms of Service</h1><p className="text-xs">Template – have it reviewed by counsel before launch.</p>
    {[["Authorised use only", "You may run assessments only against systems you own or are explicitly authorised to test. You must provide an accurate authorisation statement for each assessment. Misuse, including targeting third-party systems, will result in suspension."],
      ["Acceptable use", "Do not use ZeroDay's LLM Rakshak to generate harmful content, to attack unrelated systems, to bypass rate limits or quotas, or to probe the platform itself without written permission."],
      ["Your keys & costs", "You are responsible for provider charges incurred by your API keys. Budgets and limits reduce but do not eliminate cost risk."],
      ["No guarantee", "Results reflect behaviour at test time. A passed test is not proof of security. The service is provided as is."],
      ["Plans & billing", "Entitlements are determined by your active plan on the server. Paid plans renew until cancelled."],
      ["Termination", "We may suspend accounts that violate these terms. You may delete your data at any time."]].map(([t, b]) => <section key={t}><h2 className="text-base font-semibold text-foreground">{t}</h2><p>{b}</p></section>)}</main>;
}
