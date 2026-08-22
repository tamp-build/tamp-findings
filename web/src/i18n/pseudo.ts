// Pseudo-localisation: a synthetic locale that makes i18n defects visible
// before any real translation exists.
//
// It does three jobs at once, and each one catches a class of bug that an
// English-only build cannot:
//
//   1. Accents every letter. Anything still rendering as plain ASCII is a
//      hardcoded string that never went through the catalogue.
//   2. Pads by ~40%. German and Finnish routinely run that much longer than
//      English; padding surfaces truncation and overflow now rather than
//      after a translator is paid.
//   3. Brackets the whole string. A missing bracket means the text was cut
//      off, and interpolated values stay readable inside.
//
// Interpolation placeholders ({{count}}) and anything already inside brackets
// are left alone — mangling those would break the very substitution being
// tested.

const MAP: Record<string, string> = {
  a: 'á', b: 'ƀ', c: 'ç', d: 'ð', e: 'é', f: 'ƒ', g: 'ĝ', h: 'ĥ', i: 'í',
  j: 'ĵ', k: 'ķ', l: 'ł', m: 'ɱ', n: 'ñ', o: 'ó', p: 'þ', q: ' q', r: 'ŕ',
  s: 'ş', t: 'ţ', u: 'ú', v: 'ṽ', w: 'ŵ', x: 'ẋ', y: 'ý', z: 'ž',
  A: 'Á', B: 'Ɓ', C: 'Ç', D: 'Ð', E: 'É', F: 'Ƒ', G: 'Ĝ', H: 'Ĥ', I: 'Í',
  J: 'Ĵ', K: 'Ķ', L: 'Ł', M: 'Ṁ', N: 'Ñ', O: 'Ó', P: 'Þ', Q: 'Q', R: 'Ŕ',
  S: 'Ş', T: 'Ţ', U: 'Ú', V: 'Ṽ', W: 'Ŵ', X: 'Ẋ', Y: 'Ý', Z: 'Ž',
}

// Matches {{placeholder}} and $t(nested.key) so they survive untouched.
const PRESERVE = /(\{\{[^}]*\}\}|\$t\([^)]*\))/g

const PAD = '~'

export function pseudoize(value: string): string {
  if (!value) return value

  const transformed = value
    .split(PRESERVE)
    .map((chunk, i) =>
      // Odd indices are the captured placeholders — leave them intact.
      i % 2 === 1 ? chunk : chunk.replace(/[a-zA-Z]/g, c => MAP[c] ?? c),
    )
    .join('')

  // ~40% expansion, floored so even short labels grow enough to matter.
  const padCount = Math.max(2, Math.round(transformed.length * 0.4))
  return `[${transformed}${PAD.repeat(padCount)}]`
}

// Walk an English catalogue and produce its pseudo twin. Runs once at startup
// against the already-loaded resources, so a new key is pseudo-localised the
// moment it is added — no extraction step to forget.
export function pseudoizeCatalogue(input: unknown): unknown {
  if (typeof input === 'string') return pseudoize(input)
  if (Array.isArray(input)) return input.map(pseudoizeCatalogue)
  if (input && typeof input === 'object') {
    return Object.fromEntries(
      Object.entries(input as Record<string, unknown>)
        .map(([k, v]) => [k, pseudoizeCatalogue(v)]),
    )
  }
  return input
}
