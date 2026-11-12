"use client";
import Link from "next/link";
import { useState } from "react";
import { Button, Card, CardContent, CardHeader, CardTitle, CardDescription, Field, Input } from "@/components/ui/primitives";
import { ErrorNote } from "@/components/shared";
import { api, ApiError } from "@/lib/api";

export default function Forgot() {
  const [email, setEmail] = useState(""); const [busy, setBusy] = useState(false); const [done, setDone] = useState(false); const [err, setErr] = useState<ApiError | null>(null);
  async function submit(e: React.FormEvent) { e.preventDefault(); setBusy(true); setErr(null); try { await api("/auth/forgot-password", { method: "POST", body: { email } }); setDone(true); } catch (x) { setErr(x as ApiError); } finally { setBusy(false); } }
  return <Card><CardHeader><CardTitle className="text-base">Reset your password</CardTitle><CardDescription>We will email a one-hour reset link if the account exists.</CardDescription></CardHeader>
    <CardContent>{done ? <div className="space-y-3 text-sm"><p>If an account exists for <b>{email}</b>, a reset link has been sent.</p><Link href="/login" className="text-primary hover:underline">Back to sign in</Link></div> :
      <form onSubmit={submit} className="space-y-4"><ErrorNote error={err} /><Field label="Email"><Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" /></Field><Button type="submit" className="w-full" loading={busy}>Send reset link</Button><Link href="/login" className="block text-center text-xs text-muted-foreground hover:text-foreground">Back to sign in</Link></form>}</CardContent></Card>;
}
