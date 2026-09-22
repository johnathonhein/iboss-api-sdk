/**
 * Generated settings-field families that policy-layer and resource-policy
 * settings POSTs are expected to carry.
 *
 * Gateway `POST /json/controls/policyLayers/settings` applies defaults for
 * omitted fields (same class as DEVELOP-34251 / DEVELOP-32482). The SDK
 * update path therefore round-trips the full GET object, including every
 * catN / prioN / bypassSslMitmN member, and only fills keys the GET lacked.
 */

/** Inclusive upper bound of catN / prioN / bypassSslMitmN (111 members, 0..110). */
export const POLICY_FIELD_FAMILY_MAX = 110;

/** The 400-character all-zeros categories bitmap used in settings payloads. */
export function emptyCategoriesBitmap(): string {
  return "0".repeat(400);
}

/** Fields cat0..cat110 = 3 (category action defaults). */
export function generateCategoryFields(value = 3): Record<string, number> {
  const fields: Record<string, number> = {};
  for (let i = 0; i <= POLICY_FIELD_FAMILY_MAX; i++) fields[`cat${i}`] = value;
  return fields;
}

/** Fields prio0..prio110 = 0. */
export function generatePriorityFields(value = 0): Record<string, number> {
  const fields: Record<string, number> = {};
  for (let i = 0; i <= POLICY_FIELD_FAMILY_MAX; i++) fields[`prio${i}`] = value;
  return fields;
}

/** Fields bypassSslMitm0..bypassSslMitm110 = 0. */
export function generateBypassSslMitmFields(value = 0): Record<string, number> {
  const fields: Record<string, number> = {};
  for (let i = 0; i <= POLICY_FIELD_FAMILY_MAX; i++) fields[`bypassSslMitm${i}`] = value;
  return fields;
}

export function hasFieldFamily(
  settings: Record<string, unknown>,
  prefix: "cat" | "prio" | "bypassSslMitm",
): boolean {
  for (let i = 0; i <= POLICY_FIELD_FAMILY_MAX; i++) {
    if (settings[`${prefix}${i}`] === undefined) return false;
  }
  return true;
}

/**
 * Ensure the three generated families and a categories bitmap are present.
 * Existing values win — this never overwrites a field the GET or the caller
 * already supplied. An empty-string bitmap is kept (allowlist reads return
 * length 0); a missing bitmap is filled with 400 zeros.
 */
export function ensureFieldFamilies(settings: Record<string, unknown>): Record<string, unknown> {
  const categories =
    typeof settings.categories === "string" ? settings.categories : emptyCategoriesBitmap();
  return {
    ...generateCategoryFields(),
    ...generatePriorityFields(),
    ...generateBypassSslMitmFields(),
    ...settings,
    categories,
  };
}
