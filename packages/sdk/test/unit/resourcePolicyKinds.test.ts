import { describe, expect, it } from "vitest";
import { IbossPolicyTypeError } from "../../src/client/errors.js";
import {
  assertCreateSettingsPatch,
  buildCreateResourcePolicySettings,
} from "../../src/api/resourcePolicyCreate.js";
import {
  assertGatewayAcceptsCustomType,
  customTypeMatchesKind,
  resolveResourcePolicyKind,
  RESOURCE_POLICY_KIND_WIRE,
} from "../../src/api/resourcePolicyKinds.js";

describe("resource policy kinds (DEVELOP-34958)", () => {
  it("maps urlList and parent to enums and never to numeric 6/10", () => {
    expect(resolveResourcePolicyKind({ kind: "urlList" })).toEqual(RESOURCE_POLICY_KIND_WIRE.urlList);
    expect(resolveResourcePolicyKind({ kind: "parent" }).customType).toBe("e_custom_category_type_parent");
    expect(resolveResourcePolicyKind({ kind: "urlList" }).numeric).toBe(6);

    const urlList = buildCreateResourcePolicySettings({
      customCategoryId: 1,
      customCategoryNumber: 1001,
      name: "URL list",
      type: "categories",
      customType: RESOURCE_POLICY_KIND_WIRE.urlList.customType,
      settings: { policyAction: 0 },
    });
    expect(urlList.body.customType).toBe("e_custom_category_url_list");
    expect(JSON.stringify(urlList.body)).not.toContain('"customType":6');
    expect(urlList.verify.wireKind?.kind).toBe("urlList");
  });

  it("rejects numeric customType 6 and 10 before a request", () => {
    expect(() => assertGatewayAcceptsCustomType(6, "createLayerStructure customType")).toThrow(IbossPolicyTypeError);
    expect(() => assertGatewayAcceptsCustomType("10", "settings.customType")).toThrow(/DEVELOP-34958/);
    expect(() => assertGatewayAcceptsCustomType("e_custom_category_url_list", "customType")).not.toThrow();
    expect(() => assertCreateSettingsPatch({ customType: 6 })).toThrow(IbossPolicyTypeError);
  });

  it("rejects urlList destinations and conflicting kind/type", () => {
    expect(() =>
      buildCreateResourcePolicySettings({
        customCategoryId: 1,
        customCategoryNumber: 1001,
        name: "URL list",
        type: "categories",
        customType: "e_custom_category_url_list",
        destinations: { mode: "selectedWebCategories", categories: ["AI_SERVICES"] },
        settings: {},
      }),
    ).toThrow(/urlList/);
    expect(() => resolveResourcePolicyKind({ kind: "urlList", type: "categories" })).toThrow(/does not match/);
    expect(resolveResourcePolicyKind({ kind: "allowlist", type: "allowlist" }).kind).toBe("allowlist");
  });

  it("accepts enum, numeric alias, or categories 13 on GET", () => {
    const urlList = RESOURCE_POLICY_KIND_WIRE.urlList;
    expect(customTypeMatchesKind(6, urlList)).toBe(true);
    expect(customTypeMatchesKind("e_custom_category_url_list", urlList)).toBe(true);
    expect(customTypeMatchesKind(1, urlList)).toBe(false);
    expect(customTypeMatchesKind(13, RESOURCE_POLICY_KIND_WIRE.categories)).toBe(true);
    expect(customTypeMatchesKind(undefined, urlList)).toBe(true);
  });
});
