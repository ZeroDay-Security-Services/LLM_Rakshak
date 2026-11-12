"use client";
import Link from "next/link";
import { useState } from "react";
import { MailCheck } from "lucide-react";
import { Button, Card, CardContent, CardHeader, CardTitle, CardDescription, Field, Input } from "@/components/ui/primitives";
import { PasswordField, pwRules } from "@/components/password-field";
import { ErrorNote } from "@/components/shared";
import { api, ApiError } from "@/lib/api";

export default function Register() {
  const [f, setF] = useState({ name: "", email: "", organization: "", password: "" }); const [err, setErr] = useState<ApiError | null>(null); const [busy, setBusy] = useState(false); const [done, setDone] = useState(false);
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(null);
    if (!pwRules(f.password).every((r) => r.ok)) { setErr(new ApiError(422, "Password does not meet the requirements")); return; }
    setBusy(true);
    try { await api("/auth/register", { method: "POST", body: { ...f, organization: f.organization || undefined } }); setDone(true); } catch (x) { setErr(x as ApiError); } finally { setBusy(false); }
  }
  if (done) return <Card><CardContent className="space-y-3 p-8 text-center"><MailCheck className="mx-auto h-8 w-8 text-cyan" /><p className="font-medium">Check your email</p><p className="text-sm text-muted-foreground">If the address can be registered, a verification link is on its way. It expires in 24 hours.</p><Link href="/login" className="text-sm text-primary hover:underline">Back to sign in</Link></CardContent></Card>;
  return <Card><CardHeader><CardTitle className="text-base">Create your account</CardTitle><CardDescription>Start assessing your LLM applications.</CardDescription></CardHeader>
    <CardContent><form onSubmit={submit} className="space-y-4" noValidate><ErrorNote error={err} />
      <Field label="Full name"><Input value={f.name} onChange={set("name")} required maxLength={100} autoComplete="name" /></Field>
      <Field label="Work email"><Input type="email" value={f.email} onChange={set("email")} required autoComplete="email" /></Field>
      <Field label="Organization (optional)"><Input value={f.organization} onChange={set("organization")} maxLength={120} autoComplete="organization" /></Field>
      <Field label="Password"><PasswordField id="password" value={f.password} onChange={(v) => setF({ ...f, password: v })} autoComplete="new-password" showRules /></Field>
      <Button type="submit" className="w-full" loading={busy}>Create account</Button>
      <p className="text-center text-xs text-muted-foreground">By registering you agree to the <Link href="/terms" className="text-primary hover:underline">Terms</Link> and <Link href="/privacy" className="text-primary hover:underline">Privacy Policy</Link>. Already registered? <Link href="/login" className="text-primary hover:underline">Sign in</Link></p>
    </form></CardContent></Card>;
}
