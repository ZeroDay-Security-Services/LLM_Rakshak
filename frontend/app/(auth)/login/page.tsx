"use client";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { toast } from "sonner";
import { Button, Card, CardContent, CardHeader, CardTitle, CardDescription, Field, Input } from "@/components/ui/primitives";
import { PasswordField } from "@/components/password-field";
import { ErrorNote } from "@/components/shared";
import { api, ApiError } from "@/lib/api";

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [code, setCode] = useState("");
  const [mfa, setMfa] = useState(false); const [err, setErr] = useState<ApiError | null>(null); const [busy, setBusy] = useState(false);
  const registered = params.get("registered") === "1";
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setErr(null);
    try { await api("/auth/login", { method: "POST", body: { email, password, totp_code: mfa ? code : undefined } }); router.replace("/dashboard"); }
    catch (x) {
      const er = x as ApiError;
      if (er.status === 401 && er.headers?.get("x-mfa-required")) { setMfa(true); toast.info("Enter the 6-digit code from your authenticator app"); }
      else { setErr(er); }
    } finally { setBusy(false); }
  }
  return <Card><CardHeader><CardTitle className="text-base">Sign in</CardTitle><CardDescription>Welcome back to ZeroDay&apos;s LLM Rakshak.</CardDescription></CardHeader>
    <CardContent><form onSubmit={submit} className="space-y-4" noValidate>
      {registered && <p className="rounded-md bg-success/10 px-3 py-2 text-sm text-success">Account created — sign in to get started.</p>}
      <ErrorNote error={err} />
      <Field label="Email"><Input id="email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required disabled={mfa} /></Field>
      <Field label="Password"><PasswordField id="password" value={password} onChange={setPassword} autoComplete="current-password" /></Field>
      {mfa && <Field label="Authentication code"><Input inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} autoFocus required /></Field>}
      <Button type="submit" className="w-full" loading={busy}>{mfa ? "Verify & sign in" : "Sign in"}</Button>
      <div className="flex justify-between text-xs"><Link href="/forgot-password" className="text-primary hover:underline">Forgot password?</Link><Link href="/register" className="text-muted-foreground hover:text-foreground">Create an account</Link></div>
    </form></CardContent></Card>;
}

export default function Login() { return <Suspense><LoginForm /></Suspense>; }
