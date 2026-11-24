import { beforeEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
import { rowsUrl, usePackageRows } from './packageRows'

vi.mock('axios')

describe('rowsUrl', () => {
  it('asks for the rows layout with the page', () => {
    expect(rowsUrl({ page: 2, pageSize: 25 })).toBe('/api/packages?layout=rows&page=2&page_size=25')
  })

  it('adds only the filters that are set', () => {
    const url = rowsUrl({ q: ' left ', registry: 'npm', verdict: 'held', severity: ['critical', 'high'], sort: 'size', order: 'desc', page: 1, pageSize: 50 })
    const params = new URL(url, 'http://x').searchParams
    expect(Object.fromEntries(params)).toEqual({
      layout: 'rows',
      page: '1',
      page_size: '50',
      q: 'left',
      registry: 'npm',
      verdict: 'held',
      severity: 'critical,high',
      sort: 'size',
      order: 'desc',
    })
  })

  it('sends an order only with a sort key', () => {
    expect(rowsUrl({ order: 'desc', page: 1, pageSize: 25 })).not.toContain('order')
  })
})

describe('usePackageRows', () => {
  beforeEach(() => vi.mocked(axios.get).mockReset())

  it('keeps the answer of the last query when an earlier one returns late', async () => {
    let releaseFirst: (v: unknown) => void = () => {}
    vi.mocked(axios.get)
      .mockImplementationOnce(() => new Promise((resolve) => (releaseFirst = resolve)))
      .mockResolvedValueOnce({ data: { packages: [{ id: 'new' }], total: 1, page: 1, page_size: 25 } })
    const { rows, total, load } = usePackageRows()

    const first = load({ q: 'a', page: 1, pageSize: 25 })
    await load({ q: 'ab', page: 1, pageSize: 25 })
    releaseFirst({ data: { packages: [{ id: 'old' }], total: 9, page: 1, page_size: 25 } })
    await first

    expect(rows.value.map((r) => r.id)).toEqual(['new'])
    expect(total.value).toBe(1)
  })

  it('reports a failure without clearing the rows it already has', async () => {
    vi.mocked(axios.get)
      .mockResolvedValueOnce({ data: { packages: [{ id: 'a' }], total: 1, page: 1, page_size: 25 } })
      .mockRejectedValueOnce(new Error('Request failed with status code 502'))
    const { rows, error, load } = usePackageRows()

    await load({ page: 1, pageSize: 25 })
    await load({ page: 2, pageSize: 25 })

    expect(error.value).toContain('502')
    expect(rows.value).toHaveLength(1)
  })
})
