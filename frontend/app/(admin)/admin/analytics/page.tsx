"use client";
import { Card, CardContent, CardHeader, CardTitle, Skeleton } from "@/components/ui/primitives";
import { PageHeader } from "@/components/shared";
import { CategoryBars, SeriesChart } from "@/components/charts";
import { useApi } from "@/lib/hooks";

export default function Analytics() {
  const d = useApi<any>("/admin/analytics");
  if (!d.data) return <Skeleton className="h-96" />;
  return <><PageHeader title="Platform analytics" crumbs={[{ label: "Admin", href: "/admin" }, { label: "Analytics" }]} description="Last 30 days." />
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2"><Card><CardHeader><CardTitle>Sign-ups</CardTitle></CardHeader><CardContent><SeriesChart data={d.data.signups} name="Sign-ups" /></CardContent></Card><Card><CardHeader><CardTitle>Successful logins</CardTitle></CardHeader><CardContent><SeriesChart data={d.data.logins} color="#22d3ee" name="Logins" /></CardContent></Card>
      <Card><CardHeader><CardTitle>Assessments created</CardTitle></CardHeader><CardContent><SeriesChart data={d.data.assessments} color="#22c55e" name="Assessments" /></CardContent></Card><Card><CardHeader><CardTitle>Findings detected</CardTitle></CardHeader><CardContent><SeriesChart data={d.data.findings} color="#f97316" name="Findings" /></CardContent></Card>
      <Card className="lg:col-span-2"><CardHeader><CardTitle>Top vulnerability categories (all time)</CardTitle></CardHeader><CardContent><CategoryBars data={d.data.top_categories} /></CardContent></Card></div></>;
}
