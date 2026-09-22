/**
 * SDK-only get → deep-merge → POST for Resource Policy settings
 * (DEVELOP-34914). There is no native Gateway PATCH on this path.
 *
 * Wire path (the same one `getLayerSettings` / `updateLayerSettings` use):
 *   GET  /json/controls/policyLayers/settings?customCategoryId=…
 *   POST /json/controls/policyLayers/settings   body = full merged object
 *
 * Gateway POST applies defaults for missing fields (DEVELOP-34251 /
 * DEVELOP-32482), so the POST body must round-trip the entire GET blob
 * including catN / prioN / bypassSslMitmN. Omitted patch keys keep prior
 * values.
 *
 * TOCTOU: another writer can POST between this GET and POST. Last write
 * wins; agent v1 does not send an ETag or take a lock. That race is
 * accepted until a native Gateway merge exists (DEVELOP-34921).
 *
 * POST success (including an empty `saveIgnoredEntries`) is not treated as
 * persistence — callers re-GET and compare.
 */
import { ensureFieldFamilies } from "./policyFields.js";

/** Caller-supplied settings fields. Unknown keys are wire fields and are merged. */
export interface ResourcePolicyPatch {
  policyEnabled?: number | boolean;
  policyAction?: number;
  aiRiskEnabled?: number | boolean;
  aiRiskEngines?: string;
  aiRiskMonitoringMessage?: string;
  aiRiskMonitoringMessageEnabled?: number | boolean;
  aiRiskMonitoringMessageTitle?: string;
  linkPolicyToAllSubjects?: number | boolean;
  enableGroupAssociation?: number | boolean;
  associatedGroups?: string;
  dlpPolicyMethod?: number;
  categories?: string;
  categoriesSelectedType?: number;
  [key: string]: unknown;
}

export interface ResourcePolicySettingsSummary {
  customCategoryId: number;
  customCategoryNumber?: number;
  customCategoryName?: string;
  kind: "resource" | "layer";
  enabled: boolean;
  customType: unknown;
  policyAction?: unknown;
  dlpPolicyMethod?: unknown;
  aiRiskEnabled: boolean;
  linkPolicyToAllSubjects: boolean;
}

export interface MergeResult {
  /** Full object to POST. Never a sparse subset of `current`. */
  next: Record<string, unknown>;
  /**
   * Caller-intended values the confirming GET must show. This is the
   * normalized patch, plus `dlpPolicyMethod: 2` when the helper had to
   * fill it because both the GET and the patch omitted it.
   * Round-tripped families are in `next` (so they are sent) and in the
   * returned GET; they are not all repeated here, so a Gateway that echoes
   * a different superset does not fail the check.
   */
  verify: Record<string, unknown>;
}

const FLAG_KEYS = new Set([
  "policyEnabled",
  "aiRiskEnabled",
  "aiRiskMonitoringMessageEnabled",
  "linkPolicyToAllSubjects",
  "enableGroupAssociation",
]);

const BLOCKED_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function asFlag(value: number | boolean): number {
  return value === true || value === 1 ? 1 : 0;
}

/**
 * Deep-merge `patch` onto `base`. `undefined` patch values are skipped
 * (the base key is kept). Arrays and non-plain objects replace. Nested
 * plain objects merge key-wise. `__proto__` / `constructor` / `prototype`
 * keys are ignored.
 */
export function deepMerge(
  base: Record<string, unknown>,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined || BLOCKED_KEYS.has(key)) continue;
    const current = out[key];
    if (isPlainObject(value) && isPlainObject(current)) {
      out[key] = deepMerge(current, value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function normalizePatchFields(patch: ResourcePolicyPatch): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined || BLOCKED_KEYS.has(key)) continue;
    if (FLAG_KEYS.has(key) && (typeof value === "boolean" || value === 0 || value === 1)) {
      fields[key] = asFlag(value as number | boolean);
      continue;
    }
    fields[key] = value;
  }
  return fields;
}

function isResourcePolicy(settings: Record<string, unknown>): boolean {
  return settings.isZeroTrustResourcePolicy === 1 || settings.isZeroTrustResourcePolicy === "1";
}

/**
 * Deep-merge `patch` onto the GET blob and fill any catN / prioN /
 * bypassSslMitmN member the GET omitted. Omitted patch keys keep prior
 * values. The result is always a full settings object for the existing POST.
 */
export function mergeResourcePolicySettings(
  current: Record<string, unknown>,
  patch: ResourcePolicyPatch,
): MergeResult {
  const fieldPatch = normalizePatchFields(patch);
  let next = deepMerge(current, fieldPatch);
  next = ensureFieldFamilies(next);

  const verify: Record<string, unknown> = { ...fieldPatch };
  // Fill dlpPolicyMethod only when GET and patch both omitted it.
  if (isResourcePolicy(next) && next.dlpPolicyMethod === undefined) {
    next.dlpPolicyMethod = 2;
    verify.dlpPolicyMethod = 2;
  }

  return { next, verify };
}

export function collectVerifyFailures(
  actual: Record<string, unknown>,
  expected: Record<string, unknown>,
): string[] {
  const failures: string[] = [];
  for (const [key, value] of Object.entries(expected)) {
    if (value === undefined) continue;
    if (!valuesEqual(actual[key], value)) {
      failures.push(`${key} is ${JSON.stringify(actual[key])}, expected ${JSON.stringify(value)}`);
    }
  }
  return failures;
}

function valuesEqual(actual: unknown, expected: unknown): boolean {
  if (actual === expected) return true;
  if (typeof expected === "number" && typeof actual === "string" && actual.trim() !== "" && Number(actual) === expected) {
    return true;
  }
  if (typeof expected === "string" && typeof actual === "number" && String(actual) === expected) {
    return true;
  }
  if (typeof expected === "object" && expected !== null && typeof actual === "object" && actual !== null) {
    return JSON.stringify(actual) === JSON.stringify(expected);
  }
  return false;
}

export function summarizeResourcePolicySettings(
  settings: Record<string, unknown>,
): ResourcePolicySettingsSummary {
  return {
    customCategoryId: Number(settings.customCategoryId),
    customCategoryNumber:
      settings.customCategoryNumber === undefined ? undefined : Number(settings.customCategoryNumber),
    customCategoryName:
      typeof settings.customCategoryName === "string" ? settings.customCategoryName : undefined,
    kind: isResourcePolicy(settings) ? "resource" : "layer",
    enabled: settings.policyEnabled === 1 || settings.policyEnabled === "1" || settings.policyEnabled === true,
    customType: settings.customType,
    policyAction: settings.policyAction,
    dlpPolicyMethod: settings.dlpPolicyMethod,
    aiRiskEnabled: settings.aiRiskEnabled === 1 || settings.aiRiskEnabled === true || settings.aiRiskEnabled === "1",
    linkPolicyToAllSubjects:
      settings.linkPolicyToAllSubjects === 1 ||
      settings.linkPolicyToAllSubjects === true ||
      settings.linkPolicyToAllSubjects === "1",
  };
}
