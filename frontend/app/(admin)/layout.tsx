"use client";
import { AuthProvider } from "@/lib/auth";
import { AppShell } from "@/components/app-shell";
export default function Layout({ children }: { children: React.ReactNode }) { return <AuthProvider><AppShell admin>{children}</AppShell></AuthProvider>; }
