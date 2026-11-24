export type DownloadPeriod = '1h' | '1day' | '7day' | '30day'

export const DOWNLOAD_PERIODS: { value: DownloadPeriod; label: string }[] = [
  { value: '1h', label: '1 hour' },
  { value: '1day', label: '24 hours' },
  { value: '7day', label: '7 days' },
  { value: '30day', label: '30 days' },
]

export interface TimeSeriesPoint {
  timestamp: string
  value: number
}

export interface TimeSeries {
  period: DownloadPeriod
  registry: string
  data_points: TimeSeriesPoint[]
}

/** Axis label of one bucket: a time of day for hourly spans, a day otherwise. */
export function bucketLabel(period: DownloadPeriod, timestamp: string): string {
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return timestamp
  if (period === '1h' || period === '1day') {
    return date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })
  }
  return date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' })
}

/** "2026-11-04T00:00:00Z" as "2026-11-04", the date form the heatmap reads. */
export function isoDay(timestamp: string): string {
  return timestamp.slice(0, 10)
}
