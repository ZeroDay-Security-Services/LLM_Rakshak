"use client";
import { useState } from "react";
import { Eye, EyeOff, Check, X } from "lucide-react";
import { Input } from "@/components/ui/primitives";
export const pwRules = (p: string) => [
  { ok: p.length >= 12, label: "12+ characters" }, { ok: [/[a-z]/, /[A-Z]/, /\d/, /[^\w\s]/].filter((r) => r.test(p)).length >= 3, label: "3 of: lower, upper, digit, symbol" },
];
export function PasswordField({ id, value, onChange, autoComplete, showRules, placeholder }: { id: string; value: string; onChange: (v: string) => void; autoComplete: string; showRules?: boolean; placeholder?: string }) {
  const [show, setShow] = useState(false);
  return <div className="space-y-1.5"><div className="relative"><Input id={id} type={show ? "text" : "password"} value={value} onChange={(e) => onChange(e.target.value)} autoComplete={autoComplete} placeholder={placeholder} maxLength={128} required className="pr-9" />
    <button type="button" onClick={() => setShow(!show)} className="absolute right-2 top-2 text-muted-foreground hover:text-foreground" aria-label={show ? "Hide password" : "Show password"}>{show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div>
    {showRules && value && <ul className="flex flex-wrap gap-x-4 text-xs">{pwRules(value).map((r) => <li key={r.label} className={r.ok ? "text-success" : "text-muted-foreground"}>{r.ok ? <Check className="mr-1 inline h-3 w-3" /> : <X className="mr-1 inline h-3 w-3" />}{r.label}</li>)}</ul>}</div>;
}
