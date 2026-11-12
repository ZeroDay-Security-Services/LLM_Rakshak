"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "./api";

export function useApi<T = any>(path: string | null, params?: Record<string, any>, opts: { poll?: number } = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const key = path ? path + JSON.stringify(params ?? {}) : "";
  const alive = useRef(true);
  const load = useCallback(async (silent = false) => {
    if (!path) return;
    if (!silent) setLoading(true);
    try { const d = await api<T>(path, { params }); if (alive.current) { setData(d); setError(null); } }
    catch (e) { if (alive.current) setError(e as ApiError); }
    finally { if (alive.current) setLoading(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  useEffect(() => { alive.current = true; load(); return () => { alive.current = false; }; }, [load]);
  useEffect(() => { if (!opts.poll) return; const t = setInterval(() => load(true), opts.poll); return () => clearInterval(t); }, [opts.poll, load]);
  return { data, error, loading, reload: () => load(true), setData };
}

export function useDebounced<T>(v: T, ms = 300) {
  const [d, setD] = useState(v);
  useEffect(() => { const t = setTimeout(() => setD(v), ms); return () => clearTimeout(t); }, [v, ms]);
  return d;
}
