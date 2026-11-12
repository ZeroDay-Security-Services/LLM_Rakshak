import Link from "next/link";
export default function NotFound() {
  return <div className="flex min-h-screen flex-col items-center justify-center gap-3 text-center"><p className="text-5xl font-semibold text-primary">404</p><p className="text-sm text-muted-foreground">This page does not exist.</p><Link href="/" className="text-sm text-primary hover:underline">Back to home</Link></div>;
}
