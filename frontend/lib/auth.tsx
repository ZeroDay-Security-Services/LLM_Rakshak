"use client";
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError } from "./api";

export type Me = {
  user: { id: string; email: string; name: string; role: string; organization?: string; job_title?: string; mfa_enabled: boolean; has_avatar: boolean; preferences?: any };
  organization: { id: string; name: string }; org_role: string; permissions: string[];
  plan: { name: string; label: string; tiers: string[]; report_formats: string[]; assessments_per_month: number; max_requests_per_assessment: number; ai_analysis: boolean; custom_attacks: boolean; members: number };
  usage: { assessments: number; running: number; members: number };
};
type Ctx = { me: Me | null; loading: boolean; can: (p: string) => boolean; reload: () => Promise<void>; logout: () => Promise<void> };
const AuthCtx = createContext<Ctx>({} as Ctx);
export const useAuth = () => useContext(AuthCtx);

export function AuthProvider({ children, required = true }: { children: React.ReactNode; required?: boolean }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  const reload = useCallback(async () => {
    try { setMe(await api<Me>("/auth/me")); }
    catch (e) { setMe(null); if (required && e instanceof ApiError && e.status === 401) router.replace("/login"); }
    finally { setLoading(false); }
  }, [required, router]);
  useEffect(() => { reload(); }, [reload]);
  const logout = useCallback(async () => { try { await api("/auth/logout", { method: "POST" }); } catch {} setMe(null); router.replace("/login"); }, [router]);
  const can = useCallback((p: string) => !!me?.permissions.includes(p), [me]);
  return <AuthCtx.Provider value={{ me, loading, can, reload, logout }}>{children}</AuthCtx.Provider>;
}
