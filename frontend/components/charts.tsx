"use client";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Legend } from "recharts";
import { CATEGORY_LABELS, SEV_COLOR } from "@/lib/utils";

const tip = { contentStyle: { background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }, labelStyle: { color: "hsl(var(--muted-foreground))" }, cursor: { fill: "hsl(var(--accent) / .4)" } };
const axis = { stroke: "hsl(var(--muted-foreground))", fontSize: 11, tickLine: false, axisLine: false } as const;

export function SeverityChart({ data }: { data: { severity: string; count: number }[] }) {
  const total = data.reduce((a, b) => a + b.count, 0);
  if (!total) return <ChartEmpty text="No open vulnerabilities" />;
  return <div className="flex items-center gap-4"><ResponsiveContainer width="55%" height={190}><PieChart><Pie data={data} dataKey="count" nameKey="severity" innerRadius={50} outerRadius={78} paddingAngle={2} stroke="none">{data.map((d) => <Cell key={d.severity} fill={SEV_COLOR[d.severity]} />)}</Pie><Tooltip {...tip} /></PieChart></ResponsiveContainer>
    <ul className="space-y-1.5 text-xs">{data.map((d) => <li key={d.severity} className="flex items-center gap-2"><span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[d.severity] }} /><span className="capitalize text-muted-foreground w-16">{d.severity}</span><span className="tabular-nums font-medium">{d.count}</span></li>)}</ul></div>;
}
export function HistoryChart({ data }: { data: { date: string; created: number; completed: number; failed: number }[] }) {
  if (!data.length) return <ChartEmpty text="No assessments in the last 30 days" />;
  return <ResponsiveContainer width="100%" height={210}><AreaChart data={data} margin={{ left: -20, right: 8 }}><CartesianGrid stroke="hsl(var(--border))" vertical={false} /><XAxis dataKey="date" {...axis} tickFormatter={(d) => d.slice(5)} /><YAxis {...axis} allowDecimals={false} /><Tooltip {...tip} /><Legend wrapperStyle={{ fontSize: 11 }} />
    <Area type="monotone" dataKey="created" stroke="#3b82f6" fill="#3b82f622" name="Created" /><Area type="monotone" dataKey="completed" stroke="#22c55e" fill="#22c55e22" name="Completed" /><Area type="monotone" dataKey="failed" stroke="#ef4444" fill="#ef444422" name="Failed" /></AreaChart></ResponsiveContainer>;
}
export function ScoreTrend({ data }: { data: { date: string; score: number; name: string }[] }) {
  if (!data.length) return <ChartEmpty text="No completed assessments yet" />;
  return <ResponsiveContainer width="100%" height={210}><LineChart data={data} margin={{ left: -20, right: 8 }}><CartesianGrid stroke="hsl(var(--border))" vertical={false} /><XAxis dataKey="date" {...axis} tickFormatter={(d) => d.slice(5)} /><YAxis {...axis} domain={[0, 100]} /><Tooltip {...tip} />
    <Line type="monotone" dataKey="score" stroke="#22d3ee" strokeWidth={2} dot={{ r: 3 }} name="Score" /></LineChart></ResponsiveContainer>;
}
export function CategoryBars({ data }: { data: { category: string; count: number }[] }) {
  if (!data.length) return <ChartEmpty text="No findings by category" />;
  const d = data.map((x) => ({ ...x, name: CATEGORY_LABELS[x.category] ?? x.category })).sort((a, b) => b.count - a.count);
  return <ResponsiveContainer width="100%" height={Math.max(160, d.length * 30)}><BarChart data={d} layout="vertical" margin={{ left: 40, right: 8 }}><XAxis type="number" {...axis} allowDecimals={false} /><YAxis type="category" dataKey="name" {...axis} width={120} /><Tooltip {...tip} /><Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} name="Findings" /></BarChart></ResponsiveContainer>;
}
export function ModelComparison({ data }: { data: { model: string; score: number; findings: number }[] }) {
  if (!data.length) return <ChartEmpty text="Run assessments on two or more models to compare" />;
  return <ResponsiveContainer width="100%" height={210}><BarChart data={data} margin={{ left: -20, right: 8 }}><CartesianGrid stroke="hsl(var(--border))" vertical={false} /><XAxis dataKey="model" {...axis} /><YAxis {...axis} domain={[0, 100]} /><Tooltip {...tip} /><Legend wrapperStyle={{ fontSize: 11 }} />
    <Bar dataKey="score" fill="#22d3ee" radius={[4, 4, 0, 0]} name="Score" /><Bar dataKey="findings" fill="#f97316" radius={[4, 4, 0, 0]} name="Open findings" /></BarChart></ResponsiveContainer>;
}
export function OutcomeChart({ data }: { data: { status: string; count: number }[] }) {
  const colors: Record<string, string> = { completed: "#22c55e", failed: "#ef4444", cancelled: "#64748b" };
  if (!data.some((d) => d.count)) return <ChartEmpty text="No finished assessments" />;
  return <ResponsiveContainer width="100%" height={190}><BarChart data={data} margin={{ left: -20, right: 8 }}><XAxis dataKey="status" {...axis} /><YAxis {...axis} allowDecimals={false} /><Tooltip {...tip} /><Bar dataKey="count" radius={[4, 4, 0, 0]}>{data.map((d) => <Cell key={d.status} fill={colors[d.status]} />)}</Bar></BarChart></ResponsiveContainer>;
}
export function SeriesChart({ data, color = "#3b82f6", name }: { data: { date: string; count: number }[]; color?: string; name: string }) {
  if (!data.length) return <ChartEmpty text="No data in the last 30 days" />;
  return <ResponsiveContainer width="100%" height={170}><AreaChart data={data} margin={{ left: -20, right: 8 }}><CartesianGrid stroke="hsl(var(--border))" vertical={false} /><XAxis dataKey="date" {...axis} tickFormatter={(d) => d.slice(5)} /><YAxis {...axis} allowDecimals={false} /><Tooltip {...tip} /><Area type="monotone" dataKey="count" stroke={color} fill={color + "22"} name={name} /></AreaChart></ResponsiveContainer>;
}
export function ChartEmpty({ text }: { text: string }) { return <div className="flex h-[170px] items-center justify-center text-xs text-muted-foreground">{text}</div>; }
