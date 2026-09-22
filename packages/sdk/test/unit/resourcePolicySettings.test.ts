import { describe, expect, it } from "vitest";
import {
  emptyCategoriesBitmap,
  generateBypassSslMitmFields,
  generateCategoryFields,
  generatePriorityFields,
  hasFieldFamily,
  POLICY_FIELD_FAMILY_MAX,
} from "../../src/api/policyFields.js";
import {
  deepMerge,
  mergeResourcePolicySettings,
  collectVerifyFailures,
} from "../../src/api/resourcePolicySettings.js";
import { applyGatewayOmittedSettingsDefaults } from "../mock-server/mockIboss.js";

function currentSettings(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    customCategoryId: 1114,
    customCategoryNumber: 2114,
    customCategoryName: "Approved Apps",
    isZeroTrustResourcePolicy: 1,
    customType: "e_custom_category_type_allowlist",
    policyEnabled: 1,
    showPACUrl: 1,
    ...generateCategoryFields(),
    ...generatePriorityFields(),
    ...generateBypassSslMitmFields(),
    categories: emptyCategoriesBitmap(),
    dlpPolicyMethod: 2,
    ...overrides,
  };
}

describe("mergeResourcePolicySettings (DEVELOP-34914)", () => {
  it("keeps omitted fields, including full catN / prioN / bypassSslMitmN families", () => {
    const current = currentSettings({
      policyAction: 1,
      cat7: 9,
      prio3: 4,
      bypassSslMitm10: 1,
      aiRiskMonitoringMessage: "keep me",
      enableGroupAssociation: 0,
    });
    const snapshot = { ...current };
    const { next, verify } = mergeResourcePolicySettings(current, { aiRiskEnabled: true });
    expect(verify).toEqual({ aiRiskEnabled: 1 });

    expect(current).toEqual(snapshot);
    expect(next.aiRiskEnabled).toBe(1);
    for (const key of Object.keys(current)) {
      if (key === "aiRiskEnabled") continue;
      expect(next[key], key).toEqual(current[key]);
    }
    expect(hasFieldFamily(next, "cat")).toBe(true);
    expect(hasFieldFamily(next, "prio")).toBe(true);
    expect(hasFieldFamily(next, "bypassSslMitm")).toBe(true);
    expect(next.cat7).toBe(9);
    expect(next.prio3).toBe(4);
    expect(next.bypassSslMitm10).toBe(1);
    expect(next.showPACUrl).toBe(1);
    expect(next.aiRiskMonitoringMessage).toBe("keep me");
    for (let i = 0; i <= POLICY_FIELD_FAMILY_MAX; i++) {
      expect(next[`cat${i}`], `cat${i}`).toBeDefined();
      expect(next[`prio${i}`], `prio${i}`).toBeDefined();
      expect(next[`bypassSslMitm${i}`], `bypassSslMitm${i}`).toBeDefined();
    }
  });

  it("fills only family members the GET lacked and does not overwrite a present value", () => {
    const { next, verify } = mergeResourcePolicySettings(
      { customCategoryId: 1, isZeroTrustResourcePolicy: 1, cat7: 9 },
      { linkPolicyToAllSubjects: true },
    );
    expect(verify).toEqual({ linkPolicyToAllSubjects: 1, dlpPolicyMethod: 2 });
    expect(next.cat7).toBe(9);
    expect(next.cat0).toBe(3);
    expect(next.cat110).toBe(3);
    expect(next.prio0).toBe(0);
    expect(next.bypassSslMitm110).toBe(0);
    expect(hasFieldFamily(next, "cat")).toBe(true);
    expect(hasFieldFamily(next, "prio")).toBe(true);
    expect(hasFieldFamily(next, "bypassSslMitm")).toBe(true);
    expect(next.categories).toBe(emptyCategoriesBitmap());
    expect(next.linkPolicyToAllSubjects).toBe(1);
    expect(next.dlpPolicyMethod).toBe(2);
  });

  it("does not overwrite a prior dlpPolicyMethod when the patch omits it", () => {
    const { next } = mergeResourcePolicySettings(currentSettings({ dlpPolicyMethod: 1 }), {
      aiRiskEnabled: 1,
    });
    expect(next.dlpPolicyMethod).toBe(1);
  });

  it("skips undefined patch keys and deep-merges nested objects", () => {
    const { next } = mergeResourcePolicySettings(
      currentSettings({ aiRiskEnabled: 0, note: { a: 1, b: 2 } }),
      { aiRiskEnabled: undefined, note: { b: 3 } },
    );
    expect(next.aiRiskEnabled).toBe(0);
    expect(next.note).toEqual({ a: 1, b: 3 });
  });

  it("ignores prototype-polluting patch keys", () => {
    const patch = JSON.parse('{"__proto__": {"polluted": true}, "aiRiskEnabled": 1}') as Record<
      string,
      unknown
    >;
    const { next } = mergeResourcePolicySettings(currentSettings(), patch);
    expect(next.aiRiskEnabled).toBe(1);
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(next, "__proto__")).toBe(false);
  });

  it("keeps an empty categories string instead of inventing a 400-zero bitmap", () => {
    const { next } = mergeResourcePolicySettings(currentSettings({ categories: "" }), {
      aiRiskEnabled: 1,
    });
    expect(next.categories).toBe("");
  });
});

describe("deepMerge", () => {
  it("replaces arrays instead of concatenating them", () => {
    expect(deepMerge({ ids: [1, 2] }, { ids: [3] })).toEqual({ ids: [3] });
  });
});

describe("collectVerifyFailures", () => {
  it("reports a sent field that the confirming GET dropped", () => {
    const failures = collectVerifyFailures(
      { aiRiskEnabled: undefined, cat7: 3 },
      { aiRiskEnabled: 1, cat7: 9 },
    );
    expect(failures.some((line) => line.includes("aiRiskEnabled"))).toBe(true);
    expect(failures.some((line) => line.includes("cat7"))).toBe(true);
  });

  it("accepts numeric strings for numeric expectations", () => {
    expect(collectVerifyFailures({ aiRiskEnabled: "1", cat7: "9" }, { aiRiskEnabled: 1, cat7: 9 })).toEqual(
      [],
    );
  });
});

describe("sparse POST omit-defaults (negative control)", () => {
  it("defaults omitted families and drops unrelated prior fields", () => {
    const wiped = applyGatewayOmittedSettingsDefaults({
      customCategoryId: 1114,
      customCategoryNumber: 2114,
      customCategoryName: "Approved Apps",
      aiRiskEnabled: 1,
    });
    expect(wiped.aiRiskEnabled).toBe(1);
    expect(wiped.cat7).toBe(3);
    expect(wiped.prio3).toBe(0);
    expect(wiped.bypassSslMitm10).toBe(0);
    expect(wiped.categories).toBe(emptyCategoriesBitmap());
    expect(wiped.showPACUrl).toBeUndefined();
    expect(wiped.aiRiskMonitoringMessage).toBeUndefined();
    expect(hasFieldFamily(wiped, "cat")).toBe(true);
    expect(hasFieldFamily(wiped, "prio")).toBe(true);
    expect(hasFieldFamily(wiped, "bypassSslMitm")).toBe(true);

    const prior = currentSettings({
      cat7: 9,
      prio3: 4,
      bypassSslMitm10: 1,
      aiRiskMonitoringMessage: "keep me",
    });
    const { next } = mergeResourcePolicySettings(prior, { aiRiskEnabled: 1 });
    expect(next.cat7).toBe(9);
    expect(next.prio3).toBe(4);
    expect(next.bypassSslMitm10).toBe(1);
    expect(next.showPACUrl).toBe(1);
    expect(next.aiRiskMonitoringMessage).toBe("keep me");
    expect(Object.keys(next).length).toBeGreaterThan(Object.keys(wiped).length);
  });
});
