import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { Toaster } from "sonner";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "ZeroDay's LLM Rakshak — AI security assessment", template: "%s · ZeroDay's LLM Rakshak" },
  description: "Expose AI vulnerabilities before attackers do. Evidence-aware prompt-injection, jailbreak, leakage, tool-call and agentic security assessments with defensible reporting.",
  applicationName: "ZeroDay's LLM Rakshak",
  authors: [{ name: "ZeroDay Security Services" }],
  icons: { icon: [{ url: "/logo.jpg", type: "image/jpeg" }], apple: "/logo.jpg" },
  openGraph: {
    title: "ZeroDay's LLM Rakshak",
    description: "Expose AI vulnerabilities before attackers do.",
    siteName: "ZeroDay Security Services",
    images: [{ url: "/logo.jpg", width: 1024, height: 1024, alt: "ZeroDay Security Services" }],
    type: "website",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en" className={`dark ${GeistSans.variable} ${GeistMono.variable}`} suppressHydrationWarning>
    <body className="font-sans">{children}<Toaster theme="dark" position="bottom-right" toastOptions={{ style: { background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", color: "hsl(var(--foreground))" } }} /></body></html>;
}
