import { Logo } from "@/components/logo";
export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return <div className="relative flex min-h-screen items-center justify-center p-4"><div className="grid-bg pointer-events-none absolute inset-0" />
    <div className="relative w-full max-w-md space-y-6"><div className="flex justify-center"><Logo stacked /></div>{children}<p className="text-center text-xs text-muted-foreground">Only test systems you own or are explicitly authorised to assess.</p></div></div>;
}
