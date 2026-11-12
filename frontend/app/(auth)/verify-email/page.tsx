"use client";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/primitives";
import { api } from "@/lib/api";

function Verify() {
  const token = useSearchParams().get("token"); const [s, setS] = useState<"loading" | "ok" | "bad">("loading"); const ran = useRef(false);
  useEffect(() => { if (ran.current) return; ran.current = true; if (!token) return setS("bad"); api("/auth/verify-email", { method: "POST", body: { token } }).then(() => setS("ok")).catch(() => setS("bad")); }, [token]);
  return <Card><CardContent className="space-y-3 p-8 text-center">
    {s === "loading" && <><Loader2 className="mx-auto h-8 w-8 animate-spin text-primary" /><p className="text-sm">Verifying your email…</p></>}
    {s === "ok" && <><CheckCircle2 className="mx-auto h-8 w-8 text-success" /><p className="font-medium">Email verified</p><Link href="/login" className="text-sm text-primary hover:underline">Continue to sign in</Link></>}
    {s === "bad" && <><XCircle className="mx-auto h-8 w-8 text-danger" /><p className="font-medium">This link is invalid or has expired</p><Link href="/login" className="text-sm text-primary hover:underline">Back to sign in</Link></>}</CardContent></Card>;
}
export default function Page() { return <Suspense><Verify /></Suspense>; }
