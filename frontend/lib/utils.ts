import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
export const cn = (...i: ClassValue[]) => twMerge(clsx(i));
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const SEV_COLOR: Record<string, string> = { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#3b82f6", info: "#64748b" };
export const CATEGORY_LABELS: Record<string, string> = {
  prompt_injection: "Prompt Injection", jailbreak: "Jailbreak", sensitive_disclosure: "Sensitive Disclosure", insecure_output: "Insecure Output",
  excessive_agency: "Excessive Agency", rag_security: "RAG Security", model_dos: "Model DoS", hallucination: "Hallucination", system_prompt: "System Prompt", tool_calling: "Tool Calling",
};
export const fmtDate = (s?: string | null) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—");
export const fmtDay = (s?: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "—");
export const pct = (n?: number | null) => (n == null ? "—" : `${Math.round(n * 100)}%`);
export const scoreColor = (s?: number | null) => (s == null ? "text-muted-foreground" : s >= 90 ? "text-success" : s >= 75 ? "text-cyan" : s >= 60 ? "text-warning" : "text-danger");
export function timeAgo(s: string) {
  const d = (Date.now() - new Date(s).getTime()) / 1000;
  if (d < 60) return "just now"; if (d < 3600) return `${Math.floor(d / 60)}m ago`; if (d < 86400) return `${Math.floor(d / 3600)}h ago`; return `${Math.floor(d / 86400)}d ago`;
}
