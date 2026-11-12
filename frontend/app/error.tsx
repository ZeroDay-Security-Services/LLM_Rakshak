"use client";
import { Button } from "@/components/ui/primitives";
export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 p-6 text-center" role="alert">
    <h2 className="text-lg font-semibold">Something went wrong</h2><p className="max-w-md text-sm text-muted-foreground">An unexpected error occurred. Your data is safe. {error.digest ? `Reference: ${error.digest}` : ""}</p>
    <Button onClick={reset}>Try again</Button></div>;
}
