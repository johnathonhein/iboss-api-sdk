import { describe, expect, it } from "vitest";
import { IbossPolicyTypeError } from "../../src/client/errors.js";
import { AI_SERVICES_BIT } from "../../src/api/destinations.js";
import {
  collectVerifyFailures,
  deepMerge,
  mergeResourcePolicySettings,
} from "../../src/api/resourcePolicySettings.js";
import { applyGatewayOmittedSettingsDefaults } from "../mock-server/mockIboss.js";
import {
  emptyCategoriesBitmap,
  generateBypassSslMitmFields,
  generateCategoryFields,
  generatePriorityFields,
  hasFieldFamily,
  POLICY_FIELD_FAMILY_MAX,
} from "../../src/api/policyFields.js";

function currentSettings(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    customCategoryId: 1114,
    customCategoryNumber: 2114,
    customCategoryName: "AI Security Policy",
    isZeroTrustResourcePolicy: 1,
    customType: 3,
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
  it("omit-safe merge: omitted patch fields keep prior GET values, including full families", () => {
    const current = currentSettings({
      showPACUrl: 1,
      policyAction: 1,
      cat7: 9,
      prio3: 4,
      bypassSslMitm10: 1,
      aiRiskMonitoringMessage: "keep me",
      enableGroupAssociation: 0,
      dlpPolicyMethod: 2,
    });
    const { next } = mergeResourcePolicySettings(current, { aiRiskEnabled: 1 });

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
      expect(next[`cat${i}`]).toBeDefined();
      expect(next[`prio${i}`]).toBeDefined();
      expect(next[`bypassSslMitm${i}`]).toBeDefined();
    }
  });

  it("fills only family members the GET lacked so Gateway POST cannot default them", () => {
    const { next } = mergeResourcePolicySettings(
      { customCategoryId: 1, isZeroTrustResourcePolicy: 1, cat7: 9 },
      { linkPolicyToAllSubjects: true },
    );
    expect(next.cat7).toBe(9);
    expect(next.cat0).toBe(3);
    expect(next.cat110).toBe(3);
    expect(hasFieldFamily(next, "cat")).toBe(true);
    expect(hasFieldFamily(next, "prio")).toBe(true);
    expect(hasFieldFamily(next, "bypassSslMitm")).toBe(true);
    expect(typeof next.categories).toBe("string");
    expect((next.categories as string).length).toBe(400);
    expect(next.linkPolicyToAllSubjects).toBe(1);
    expect(next.dlpPolicyMethod).toBe(2);
  });

  it("does not overwrite a prior dlpPolicyMethod when the patch omits it", () => {
    const { next } = mergeResourcePolicySettings(currentSettings({ dlpPolicyMethod: 1 }), {
      aiRiskEnabled: 1,
    });
    expect(next.dlpPolicyMethod).toBe(1);
  });

  it("encodes destinations without the agent sending a bitmap", () => {
    const { next, verify } = mergeResourcePolicySettings(currentSettings(), {
      destinations: { mode: "selectedWebCategories", categories: ["AI_SERVICES"] },
    });
    expect(next.categoriesSelectedType).toBe(0);
    expect((next.categories as string)[AI_SERVICES_BIT]).toBe("1");
    expect(verify.bits).toEqual([AI_SERVICES_BIT]);
    expect(verify.categoriesSelectedType).toBe(0);
  });

  it("rejects allowlist + categories (silent bitmap drop)", () => {
    expect(() =>
      mergeResourcePolicySettings(currentSettings({ customType: 1 }), {
        destinations: { mode: "selectedWebCategories", categories: ["AI_SERVICES"] },
      }),
    ).toThrow(IbossPolicyTypeError);
  });

  it("warns instead of encoding when onWrongType is warn", () => {
    const { next, warning, verify } = mergeResourcePolicySettings(currentSettings({ customType: 1 }), {
      destinations: { mode: "selectedWebCategories", categories: ["AI_SERVICES"] },
      onWrongType: "warn",
      aiRiskEnabled: 1,
    });
    expect(warning).toMatch(/silently drops/);
    expect(next.categoriesSelectedType).toBeUndefined();
    expect(verify.bits).toEqual([]);
    expect(next.aiRiskEnabled).toBe(1);
  });

  it("still round-trips families when advanced is set (no native Gateway PATCH)", () => {
    const current = currentSettings({ cat7: 9 });
    const { next } = mergeResourcePolicySettings(current, { aiRiskEnabled: 1, advanced: true });
    expect(next.aiRiskEnabled).toBe(1);
    expect(next.cat7).toBe(9);
    expect(hasFieldFamily(next, "cat")).toBe(true);
  });

  it("validates aiRiskEngines before POST", () => {
    expect(() =>
      mergeResourcePolicySettings(currentSettings(), { aiRiskEngines: "ChatGPT" }),
    ).toThrow(/Unknown aiRiskEngines/);
    const { next } = mergeResourcePolicySettings(currentSettings(), { aiRiskEngines: "all" });
    expect(next.aiRiskEngines).toBe("chatgpt,claude,gemini,copilot,perplexity");
  });
});

describe("collectVerifyFailures", () => {
  it("treats a successful POST with an empty bitmap as a failure", () => {
    const failures = collectVerifyFailures(
      { customType: 1, categories: "", categoriesSelectedType: undefined, aiRiskEnabled: 1 },
      {
        requireCategoriesType: true,
        categoriesSelectedType: 0,
        bits: [AI_SERVICES_BIT],
        fields: { aiRiskEnabled: 1 },
      },
    );
    expect(failures.some((f) => f.includes("bit 110"))).toBe(true);
    expect(failures.some((f) => f.includes("customType"))).toBe(true);
  });

  it("passes when bit 110, type 0, and patched fields persist", () => {
    const bitmap = emptyCategoriesBitmap().split("");
    bitmap[AI_SERVICES_BIT] = "1";
    const failures = collectVerifyFailures(
      {
        customType: 13,
        categories: bitmap.join(""),
        categoriesSelectedType: 0,
        aiRiskEnabled: 1,
        dlpPolicyMethod: 2,
      },
      {
        requireCategoriesType: true,
        categoriesSelectedType: 0,
        bits: [AI_SERVICES_BIT],
        fields: { aiRiskEnabled: 1, dlpPolicyMethod: 2 },
      },
    );
    expect(failures).toEqual([]);
  });

  it("reports a sent field that the confirming GET dropped", () => {
    const failures = collectVerifyFailures(
      { aiRiskEnabled: undefined, cat7: 3 },
      { bits: [], fields: { aiRiskEnabled: 1, cat7: 9 }, requireCategoriesType: false },
    );
    expect(failures.some((line) => line.includes("aiRiskEnabled"))).toBe(true);
    expect(failures.some((line) => line.includes("cat7"))).toBe(true);
  });

  it("accepts numeric strings for numeric expectations and does not treat blank as zero", () => {
    expect(
      collectVerifyFailures(
        { aiRiskEnabled: "1", cat7: "9" },
        { bits: [], fields: { aiRiskEnabled: 1, cat7: 9 }, requireCategoriesType: false },
      ),
    ).toEqual([]);
    const blank = collectVerifyFailures(
      { aiRiskEnabled: "" },
      { bits: [], fields: { aiRiskEnabled: 0 }, requireCategoriesType: false },
    );
    expect(blank.some((line) => line.includes("aiRiskEnabled"))).toBe(true);
  });
});

describe("omit-safe patch details (DEVELOP-34914)", () => {
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
