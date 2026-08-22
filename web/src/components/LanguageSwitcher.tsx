import { useTranslation } from 'react-i18next'
import { Languages } from 'lucide-react'
import { PSEUDO_LOCALE, SUPPORTED_LOCALES } from '@/i18n'
import { cn } from '@/lib/utils'

// Locale picker. Intentionally plain — the redesign will restyle or relocate
// this; what matters now is that switching works and persists.
//
// The pseudo-locale is listed rather than hidden behind a flag: it is a QA
// tool that only earns its keep if it is one click away, and this app is not
// public-facing.
export function LanguageSwitcher({ className }: { className?: string }) {
  const { i18n, t } = useTranslation()

  const current = SUPPORTED_LOCALES.find(l => l.code === i18n.language)?.code
    // A browser reporting fr-CA resolves to the fr catalogue; keep the select
    // showing the resolved base rather than blanking out.
    ?? SUPPORTED_LOCALES.find(l => l.code === i18n.language?.split('-')[0])?.code
    ?? 'en'

  return (
    <label className={cn('inline-flex items-center gap-1.5 text-xs text-muted-foreground', className)}>
      <Languages className="size-3.5" aria-hidden="true" />
      <span className="sr-only">{t('language.label')}</span>
      <select
        value={current}
        onChange={e => void i18n.changeLanguage(e.target.value)}
        className="rounded-md border border-border bg-background px-1.5 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
      >
        {SUPPORTED_LOCALES.map(l => (
          <option key={l.code} value={l.code}>
            {l.code === PSEUDO_LOCALE ? t('language.pseudo') : l.labelKey}
          </option>
        ))}
      </select>
    </label>
  )
}
