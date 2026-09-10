import { ReactNode } from 'react'
import { ResponsiveContainer, AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Cell, LabelList } from 'recharts'
import { SERIES, rcAxis, INK, INK2, MUTED, GRID, CURSOR } from '../lib/chartTheme'

/** Recharts tooltip: value leads, series name follows, line-key per series. */
export function RcTip({ active, payload, label, fmt }: any) {
  if (!active || !payload?.length) return null
  return (
    <div className="tip">
      <div style={{ color: INK2, marginBottom: 4 }}>{fmt ? fmt(label) : label}</div>
      {payload.filter((p: any) => p.value).map((p: any) => (
        <div key={p.dataKey} className="row" style={{ gap: 6 }}>
          <span style={{ width: 10, height: 2, background: p.color || p.fill, display: 'inline-block' }} />
          <b style={{ color: INK, fontVariantNumeric: 'tabular-nums' }}>{p.value.toLocaleString()}</b>
          <span>{p.name}</span>
        </div>
      ))}
    </div>
  )
}

const shortDay = (d: string) => { const t = Date.parse(d); return isNaN(t) ? d : new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short' }) }

export function StackedArea({ data, keys, xKey = 'day', height = 240, colors }: { data: any[]; keys: string[]; xKey?: string; height?: number; colors?: string[] }) {
  colors = colors || SERIES
  return (
    <div>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
          <CartesianGrid stroke={GRID} vertical={false} />
          <XAxis dataKey={xKey} {...rcAxis} tickFormatter={shortDay} minTickGap={24} />
          <YAxis {...rcAxis} allowDecimals={false} width={44} />
          <Tooltip content={<RcTip fmt={shortDay} />} cursor={{ stroke: INK2, strokeOpacity: 0.4 }} />
          {keys.map((k, i) => (
            <Area key={k} type="monotone" dataKey={k} name={k} stackId="1" stroke={colors[i % colors.length]} strokeWidth={2}
              fill={colors[i % colors.length]} fillOpacity={0.16} isAnimationActive={false} />
          ))}
        </AreaChart>
      </ResponsiveContainer>
      <div className="legend" style={{ marginTop: 6 }}>
        {keys.map((k, i) => <span key={k}><i style={{ background: colors[i % colors.length] }} />{k}</span>)}
      </div>
    </div>
  )
}

/** Horizontal bar, one series (slot-1 hue), bars clickable, value at the tip. */
export function HBar({ data, label, value, onClick, height, color, colorFn, fmtLabel }: {
  data: any[]; label: string; value: string; onClick?: (d: any) => void; height?: number; color?: string; colorFn?: (d: any) => string; fmtLabel?: (s: string) => string
}) {
  const h = height || Math.max(120, data.length * 30 + 10)
  return (
    <ResponsiveContainer width="100%" height={h}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 40, left: 0, bottom: 0 }} barCategoryGap={6}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey={label} width={170} tick={{ fill: INK2, fontSize: 12 }} tickLine={false} axisLine={false}
          tickFormatter={(s: string) => { const t = fmtLabel ? fmtLabel(s) : s; return t && t.length > 26 ? t.slice(0, 25) + '…' : t }} />
        <Tooltip content={<RcTip />} cursor={{ fill: CURSOR }} />
        <Bar dataKey={value} name={value === 'n' ? 'count' : value} radius={[0, 4, 4, 0]} maxBarSize={18} onClick={(d: any) => onClick?.(d.payload || d)}
          style={{ cursor: onClick ? 'pointer' : 'default' }} isAnimationActive={false}>
          {data.map((d, i) => <Cell key={i} fill={colorFn ? colorFn(d) : color || SERIES[0]} />)}
          <LabelList dataKey={value} position="right" fill={MUTED} fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function Columns({ data, x, y, height = 200, color, fmtX }: { data: any[]; x: string; y: string; height?: number; color?: string; fmtX?: (s: string) => string }) {
  color = color || SERIES[0]
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 4, left: -16, bottom: 0 }}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey={x} {...rcAxis} tickFormatter={fmtX} minTickGap={16} />
        <YAxis {...rcAxis} allowDecimals={false} width={40} />
        <Tooltip content={<RcTip fmt={fmtX} />} cursor={{ fill: CURSOR }} />
        <Bar dataKey={y} name="count" fill={color} radius={[4, 4, 0, 0]} maxBarSize={24} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function Spark({ data, k, color, height = 36 }: { data: any[]; k: string; color?: string; height?: number }) {
  color = color || SERIES[0]
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
        <Area type="monotone" dataKey={k} stroke={color} strokeWidth={2} fill={color} fillOpacity={0.12} isAnimationActive={false} dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function ChartBox({ height, children }: { height: number; children: ReactNode }) {
  return <div style={{ height, position: 'relative' }}>{children}</div>
}
