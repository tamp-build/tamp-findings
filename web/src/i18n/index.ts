import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import en from './locales/en/common.json'
import { pseudoizeCatalogue } from './pseudo'

// Locale identifier for the QA pseudo-locale. `en-XA` is the BCP-47 private-use
// convention Chrome and Android use for exactly this, so tooling that inspects
// <html lang> treats it as a legitimate tag rather than choking.
export const PSEUDO_LOCALE = 'en-XA'

export const SUPPORTED_LOCALES = [
  { code: 'en', labelKey: 'English' },
  { code: PSEUDO_LOCALE, labelKey: 'Pseudo (QA)' },
] as const

export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number]['code']

// Where an explicit user choice is remembered. Detection order below prefers
// this over the browser, so a deliberate switch survives a reload.
const STORAGE_KEY = 'tamp.findings.locale'

export const DEFAULT_NS = 'common'

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { [DEFAULT_NS]: en },
      // Generated from the English catalogue at startup rather than checked
      // in, so it can never drift out of sync with the source strings.
      [PSEUDO_LOCALE]: { [DEFAULT_NS]: pseudoizeCatalogue(en) as typeof en },
    },
    fallbackLng: 'en',
    // Region variants fall back to their base language: a browser reporting
    // fr-CA gets the fr catalogue rather than dropping to English.
    nonExplicitSupportedLngs: true,
    supportedLngs: SUPPORTED_LOCALES.map(l => l.code),
    defaultNS: DEFAULT_NS,
    ns: [DEFAULT_NS],
    detection: {
      // Explicit choice wins; then the browser's own preference list; the
      // <html lang> attribute is the last resort. No cookie — this is a
      // per-device preference, not something to send on every request.
      order: ['localStorage', 'navigator', 'htmlTag'],
      lookupLocalStorage: STORAGE_KEY,
      caches: ['localStorage'],
    },
    interpolation: {
      // React escapes for us; double-escaping mangles anything with an
      // ampersand (POA&M appears throughout this UI).
      escapeValue: false,
    },
    returnNull: false,
  })

// Keep the document in sync with the active locale. `lang` drives screen-reader
// pronunciation and browser hyphenation; `dir` is set here so that adding an
// RTL locale later is a one-line change rather than an audit of every layout.
const RTL_LANGUAGES = new Set(['ar', 'he', 'fa', 'ur'])

function applyDocumentLocale(lng: string) {
  const base = lng.split('-')[0]
  document.documentElement.lang = lng
  document.documentElement.dir = RTL_LANGUAGES.has(base) ? 'rtl' : 'ltr'
}

applyDocumentLocale(i18n.language || 'en')
i18n.on('languageChanged', applyDocumentLocale)

export default i18n
