/**
 * Resolve a possibly-localized value. Localized fields are authored as `{ en, vi }`
 * (the inner value may be a string or an array); plain values pass through unchanged,
 * with English as the fallback when a locale is missing.
 */
export function loc(value, locale) {
  if (value && typeof value === "object" && !Array.isArray(value) && "en" in value) {
    return value[locale] ?? value.en;
  }
  return value;
}
