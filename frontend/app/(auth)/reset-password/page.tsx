"use client";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { toast } from "sonner";
import { Button, Card, CardContent, CardHeader, CardTitle, Field } from "@/components/ui/primitives";
import { PasswordField, pwRules } from "@/components/password-field";
import { ErrorNote } from "@/components/shared";
import { api, ApiError } from "@/lib/api";

function Form() {
  const token = useSearchParams().get("token") ?? ""; const router = useRouter();
  const [pw, setPw] = useState(""); const [busy, setBusy] = useState(false); const [err, setErr] = useState<ApiError | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(null);
    if (!pwRules(pw).every((r) => r.ok)) return setErr(new ApiError(422, "Password does not meet the requirements"));
    setBusy(true);
    try { await api("/auth/reset-password", { method: "POST", body: { token, password: pw } }); toast.success("Password updated"); router.replace("/login"); } catch (x) { setErr(x as ApiError); } finally { setBusy(false); }
  }
  if (!token) return <Card><CardContent className="p-8 text-center text-sm">This reset link is invalid. <Link href="/forgot-password" className="text-primary hover:underline">Request a new one</Link>.</CardContent></Card>;
  return <Card><CardHeader><CardTitle className="text-base">Choose a new password</CardTitle></CardHeader><CardContent><form onSubmit={submit} className="space-y-4"><ErrorNote error={err} /><Field label="New password"><PasswordField id="pw" value={pw} onChange={setPw} autoComplete="new-password" showRules /></Field><Button type="submit" className="w-full" loading={busy}>Update password</Button></form></CardContent></Card>;
}
export default function Reset() { return <Suspense><Form /></Suspense>; }
