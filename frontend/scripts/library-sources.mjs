// Lists the @source lines for the @perfect-design/ui dist directories the app imports, transitively.
// `node scripts/library-sources.mjs` prints them; `--write` rewrites the block in src/styles/main.css.
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join, dirname, resolve, relative } from 'node:path'

export function librarySources(root) {
  const dist = join(root, 'node_modules/@perfect-design/ui/dist')

  function walk(dir, out = []) {
    for (const e of readdirSync(dir)) {
      const p = join(dir, e)
      statSync(p).isDirectory() ? walk(p, out) : out.push(p)
    }
    return out
  }

  // names imported from the package entry
  const names = new Set()
  for (const f of walk(join(root, 'src')).filter((f) => /\.(vue|ts)$/.test(f) && !/\.(spec|test)\./.test(f))) {
    const src = readFileSync(f, 'utf8')
    for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from\s*'@perfect-design\/ui'/g))
      for (const n of m[1].split(',')) {
        const name = n.trim().replace(/^type\s+/, '').split(/\s+as\s+/)[0]
        if (name && !n.trim().startsWith('type ')) names.add(name)
      }
  }

  // name -> file: follow the barrel index.js re-exports
  const resolveJs = (from, spec) => {
    const base = resolve(dirname(from), spec)
    for (const c of [base, base + '.js', join(base, 'index.js')]) if (existsSync(c) && statSync(c).isFile()) return c
    return null
  }
  const exportsOf = new Map() // exported name -> file
  {
    const idx = join(dist, 'index.js')
    const src = readFileSync(idx, 'utf8')
    const localFile = new Map()
    for (const m of src.matchAll(/^import\s+(?:(\w+)\s*,?\s*)?(?:\{([^}]*)\})?\s*from\s*"(\.[^"]+)";?$/gm)) {
      const target = resolveJs(idx, m[3])
      if (!target) continue
      if (m[1]) localFile.set(m[1], target)
      if (m[2]) for (const n of m[2].split(',')) { const p = n.trim().split(/\s+as\s+/); if (p[0]) localFile.set(p[1] ?? p[0], target) }
    }
    for (const m of src.matchAll(/^export\s*\{([^}]*)\};?$/gm))
      for (const n of m[1].split(',')) {
        const p = n.trim().split(/\s+as\s+/)
        const local = p[0], exported = p[1] ?? p[0]
        if (localFile.has(local)) exportsOf.set(exported, localFile.get(local))
      }
  }
  const files = new Set()
  const queue = []
  const missing = []
  for (const n of names) {
    const f = exportsOf.get(n)
    f ? queue.push(f) : missing.push(n)
  }
  while (queue.length) {
    const f = queue.pop()
    if (files.has(f)) continue
    files.add(f)
    const src = readFileSync(f, 'utf8')
    for (const m of src.matchAll(/from\s*["'](\.[^"']+)["']/g)) {
      const t = resolveJs(f, m[1])
      if (t && !files.has(t)) queue.push(t)
    }
  }
  const dirs = new Set([...files].map((f) => dirname(f)))
  if (missing.length) throw new Error(`not exported by @perfect-design/ui: ${missing.join(', ')}`)
  const rel = (d) => relative(join(root, 'src/styles'), d).split('\\').join('/')
  const lines = [...dirs]
    .map(rel)
    .sort()
    .map((d) => `@source "${d}/*.js";`)
  return lines
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  const lines = librarySources(root)
  if (process.argv.includes('--write')) {
    const css = join(root, 'src/styles/main.css')
    const kept = readFileSync(css, 'utf8')
      .split('\n')
      .filter((l) => !l.startsWith('@source '))
    const at = kept.findIndex((l) => l.startsWith('/* Only the library components'))
    kept.splice(at + 1, 0, ...lines)
    writeFileSync(css, kept.join('\n'))
  } else {
    console.log(lines.join('\n'))
  }
}
