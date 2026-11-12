"use client";
import * as React from "react";
import * as DialogP from "@radix-ui/react-dialog";
import * as TabsP from "@radix-ui/react-tabs";
import * as SwitchP from "@radix-ui/react-switch";
import * as LabelP from "@radix-ui/react-label";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { Loader2, X } from "lucide-react";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50",
  { variants: {
    variant: { default: "bg-primary text-primary-foreground hover:bg-primary/90", secondary: "bg-secondary text-secondary-foreground hover:bg-accent", outline: "border border-input bg-transparent hover:bg-accent", ghost: "hover:bg-accent", destructive: "bg-danger text-white hover:bg-danger/90", link: "text-primary underline-offset-4 hover:underline" },
    size: { default: "h-9 px-4", sm: "h-8 px-3 text-xs", lg: "h-11 px-6", icon: "h-9 w-9" } },
    defaultVariants: { variant: "default", size: "default" } });
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> { asChild?: boolean; loading?: boolean }
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(({ className, variant, size, asChild, loading, children, disabled, ...p }, ref) => {
  const C: any = asChild ? Slot : "button";
  return <C ref={ref} className={cn(buttonVariants({ variant, size }), className)} disabled={disabled || loading} {...p}>{asChild ? children : <>{loading && <Loader2 className="h-4 w-4 animate-spin" />}{children}</>}</C>;
});
Button.displayName = "Button";

export const Card = ({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) => <div className={cn("rounded-lg border bg-card text-card-foreground", className)} {...p} />;
export const CardHeader = ({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) => <div className={cn("flex flex-col gap-1 p-5 pb-3", className)} {...p} />;
export const CardTitle = ({ className, ...p }: React.HTMLAttributes<HTMLHeadingElement>) => <h3 className={cn("text-sm font-semibold tracking-tight", className)} {...p} />;
export const CardDescription = ({ className, ...p }: React.HTMLAttributes<HTMLParagraphElement>) => <p className={cn("text-xs text-muted-foreground", className)} {...p} />;
export const CardContent = ({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) => <div className={cn("p-5 pt-2", className)} {...p} />;

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(({ className, ...p }, ref) =>
  <input ref={ref} className={cn("flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50", className)} {...p} />);
Input.displayName = "Input";
export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(({ className, ...p }, ref) =>
  <textarea ref={ref} className={cn("flex min-h-[80px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring", className)} {...p} />);
Textarea.displayName = "Textarea";
export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(({ className, ...p }, ref) =>
  <select ref={ref} className={cn("flex h-9 w-full rounded-md border border-input bg-card px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50", className)} {...p} />);
Select.displayName = "Select";
export const Label = ({ className, ...p }: React.ComponentProps<typeof LabelP.Root>) => <LabelP.Root className={cn("text-xs font-medium text-muted-foreground", className)} {...p} />;
export const Field = ({ label, hint, error, children }: { label: string; hint?: string; error?: string; children: React.ReactNode }) =>
  <div className="space-y-1.5"><Label>{label}</Label>{children}{hint && !error && <p className="text-xs text-muted-foreground">{hint}</p>}{error && <p className="text-xs text-danger" role="alert">{error}</p>}</div>;

export const Switch = ({ className, ...p }: React.ComponentProps<typeof SwitchP.Root>) =>
  <SwitchP.Root className={cn("peer inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring data-[state=checked]:bg-primary data-[state=unchecked]:bg-input", className)} {...p}>
    <SwitchP.Thumb className="pointer-events-none block h-4 w-4 rounded-full bg-white shadow transition-transform data-[state=checked]:translate-x-4 data-[state=unchecked]:translate-x-0" /></SwitchP.Root>;

export const Skeleton = ({ className }: { className?: string }) => <div className={cn("animate-pulse rounded-md bg-accent/60", className)} />;

export const Tabs = TabsP.Root;
export const TabsList = ({ className, ...p }: React.ComponentProps<typeof TabsP.List>) => <TabsP.List className={cn("inline-flex h-9 items-center gap-1 rounded-lg bg-muted p-1 overflow-x-auto max-w-full", className)} {...p} />;
export const TabsTrigger = ({ className, ...p }: React.ComponentProps<typeof TabsP.Trigger>) => <TabsP.Trigger className={cn("inline-flex items-center whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium text-muted-foreground transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring data-[state=active]:bg-card data-[state=active]:text-foreground data-[state=active]:shadow", className)} {...p} />;
export const TabsContent = ({ className, ...p }: React.ComponentProps<typeof TabsP.Content>) => <TabsP.Content className={cn("mt-4 focus-visible:outline-none", className)} {...p} />;

export const Dialog = DialogP.Root;
export function DialogContent({ title, description, children, className }: { title: string; description?: string; children: React.ReactNode; className?: string }) {
  return <DialogP.Portal>
    <DialogP.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0" />
    <DialogP.Content className={cn("fixed left-1/2 top-1/2 z-50 w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-lg border bg-card p-6 shadow-2xl max-h-[90vh] overflow-y-auto data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95", className)}>
      <DialogP.Title className="text-base font-semibold">{title}</DialogP.Title>
      <DialogP.Description className={cn("mt-1 text-sm text-muted-foreground", !description && "sr-only")}>{description ?? title}</DialogP.Description>
      <div className="mt-4">{children}</div>
      <DialogP.Close className="absolute right-4 top-4 rounded-sm opacity-70 hover:opacity-100 focus-visible:ring-2 focus-visible:ring-ring" aria-label="Close"><X className="h-4 w-4" /></DialogP.Close>
    </DialogP.Content></DialogP.Portal>;
}
export const DialogTrigger = DialogP.Trigger;
export const DialogClose = DialogP.Close;

export const Table = ({ className, ...p }: React.HTMLAttributes<HTMLTableElement>) => <div className="w-full overflow-x-auto"><table className={cn("w-full text-sm", className)} {...p} /></div>;
export const Th = ({ className, ...p }: React.ThHTMLAttributes<HTMLTableCellElement>) => <th className={cn("h-9 px-3 text-left align-middle text-xs font-medium uppercase tracking-wide text-muted-foreground whitespace-nowrap", className)} {...p} />;
export const Td = ({ className, ...p }: React.TdHTMLAttributes<HTMLTableCellElement>) => <td className={cn("px-3 py-2.5 align-middle", className)} {...p} />;
export const Tr = ({ className, ...p }: React.HTMLAttributes<HTMLTableRowElement>) => <tr className={cn("border-b transition-colors hover:bg-accent/40", className)} {...p} />;

export function Progress({ value, className, color }: { value: number; className?: string; color?: string }) {
  return <div className={cn("h-2 w-full overflow-hidden rounded-full bg-secondary", className)} role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
    <div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${Math.max(0, Math.min(100, value))}%`, background: color }} /></div>;
}
