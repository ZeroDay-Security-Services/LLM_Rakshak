"use client";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { toast } from "sonner";
import { Button, Card, CardContent } from "@/components/ui/primitives";
import { ErrorNote } from "@/components/shared";
import { api, ApiError } from "@/lib/api";

function Accept() {
  const token = useSearchParams().get("token"); const router = useRouter(); const [busy, setBusy] = useState(false); const [err, setErr] = useState<ApiError | null>(null);
  async function go() { setBusy(true); try { await api("/orgs/invitations/accept", { method: "POST", body: { token } }); toast.success("You joined the organization"); router.replace("/dashboard"); } catch (x) { const e = x as ApiError; if (e.status === 401) router.replace("/login"); else setErr(e); } finally { setBusy(false); } }
  return <Card><CardContent className="space-y-4 p-8 text-center"><p className="font-medium">Join organization</p><p className="text-sm text-muted-foreground">Sign in with the invited email address, then accept.</p><ErrorNote error={err} />
    <Button onClick={go} loading={busy} disabled={!token}>Accept invitation</Button><div><Link href="/login" className="text-xs text-primary hover:underline">Sign in first</Link></div></CardContent></Card>;
}
export default function Page() { return <Suspense><Accept /></Suspense>; }
