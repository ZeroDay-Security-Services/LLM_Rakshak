import Link from "next/link";
import Image from "next/image";

type LogoProps = {
  href?: string;
  compact?: boolean;
  stacked?: boolean;
  className?: string;
};

/**
 * Renders the supplied ZeroDay Security Services logo. The same image is used
 * in the web UI, the HTML report and the PDF report — no generated substitutes.
 */
export function Logo({ href = "/", compact, stacked, className }: LogoProps) {
  const size = compact ? "h-10 w-10" : stacked ? "h-44 w-44" : "h-11 w-11";
  return (
    <Link
      href={href}
      className={`flex items-center gap-2.5 font-semibold tracking-tight ${className ?? ""}`}
      aria-label="ZeroDay Security Services — LLM Rakshak home"
    >
      <Image
        src="/logo.jpg"
        alt="ZeroDay Security Services"
        width={1024}
        height={1024}
        priority
        unoptimized
        className={`${size} shrink-0 rounded-md object-cover ring-1 ring-white/10`}
      />
      {!compact && (
        <span className={stacked ? "sr-only" : "hidden text-sm sm:inline"}>
          ZeroDay&apos;s <span className="text-primary">LLM Rakshak</span>
        </span>
      )}
    </Link>
  );
}
