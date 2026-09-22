import { describe, expect, it } from "vitest";
import { IbossClient } from "../../src/client/IbossClient.js";
import { IbossPolicyTypeError, IbossVerifyError } from "../../src/client/errors.js";
import { CLOUD_HOST, GATEWAY_HOST, MOCK_API_KEY } from "../mock-server/fixtures.js";
import { createMockState, mockFetch } from "../mock-server/mockIboss.js";

function makeClient(state = createMockState()) {
  return new IbossClient({
    domain: CLOUD_HOST,
    credentials: { apiKey: MOCK_API_KEY },
    fetch: mockFetch(state),
  });
}

describe("Braxton resource-policy kinds (DEVELOP-34958)", () => {
  it("createResourcePolicy({ kind: 'urlList' }) sends the enum, not numeric 6", async () => {
    const state = createMockState();
    const client = makeClient(state);
    const policy = await client.policies.createResourcePolicy({
      kind: "urlList",
      name: "Blocked URLs",
      settings: { policyAction: 0 },
    });

    expect(state.policyLayers[0]).toMatchObject({
      customType: "e_custom_category_url_list",
      isZeroTrustResourcePolicy: 1,
    });
    expect(state.layerSettings[0]?.customType).toBe("e_custom_category_url_list");
    expect(JSON.stringify(state.policyLayers[0])).not.toMatch(/"customType":6/);
    expect(policy.wireKind).toEqual({
      kind: "urlList",
      customType: "e_custom_category_url_list",
      numeric: 6,
      listKind: "resourcePolicy",
      echoedByGateway: false,
    });
    expect(policy.observedCustomType).toBe(6);
    expect(policy.settings.dlpPolicyMethod).toBe(2);
  });

  it("createResourcePolicy({ kind: 'parent' }) sends e_custom_category_type_parent", async () => {
    const state = createMockState();
    const client = makeClient(state);
    const policy = await client.policies.createResourcePolicy({
      kind: "parent",
      name: "Group",
    });
    expect(state.policyLayers[0]?.customType).toBe("e_custom_category_type_parent");
    expect(policy.wireKind.numeric).toBe(10);
    expect(policy.wireKind.echoedByGateway).toBe(false);
    expect(policy.observedCustomType).toBe(10);
  });

  it("rejects numeric 6/10 and urlList destinations before PUT", async () => {
    const state = createMockState();
    const client = makeClient(state);
    await expect(
      client.policies.createLayerStructure({
        name: "Bad",
        type: "categories",
        extra: { customType: 6 },
      }),
    ).rejects.toBeInstanceOf(IbossPolicyTypeError);
    await expect(
      client.policies.createResourcePolicy({
        kind: "urlList",
        name: "URLs",
        destinations: { mode: "selectedWebCategories", categories: ["AI_SERVICES"] },
      }),
    ).rejects.toBeInstanceOf(IbossPolicyTypeError);
    expect(state.policyLayers).toHaveLength(0);
    expect(state.requests.some((line) => line.startsWith("PUT"))).toBe(false);
  });
});

describe("moveProxyAclRule (DEVELOP-34959)", () => {
  const starting = [
    { index: 0, name: "A" },
    { index: 1, name: "B" },
    { index: 2, name: "C" },
    { index: 3, name: "D" },
  ];

  it("verifies order after the position POST", async () => {
    const state = createMockState();
    state.proxyAclRules = starting.map((rule) => ({ ...rule }));
    const client = makeClient(state);
    const result = await client.network.moveProxyAclRule({ id: 1, toId: 3 });
    expect(result.moved).toBe(true);
    expect(result.orderRevision).toBeNull();
    expect(result.orderAfter).toEqual(["name:A", "name:C", "name:D", "name:B"]);
    expect(result.attempts).toBe(1);
    expect(state.proxyAclRules.map((rule) => rule.name)).toEqual(["A", "C", "D", "B"]);
    expect(
      state.requests.filter((line) => line === `POST ${GATEWAY_HOST}/json/network/proxy/acl/rule/position`),
    ).toHaveLength(1);
  });

  it("resolves beforeRuleId without sending that query name", async () => {
    const state = createMockState();
    state.proxyAclRules = starting.map((rule) => ({ ...rule }));
    const client = makeClient(state);
    const result = await client.network.moveProxyAclRule({ id: 0, beforeRuleId: 2 });
    expect(result.toIndex).toBe(1);
    expect(result.orderAfter).toEqual(["name:B", "name:A", "name:C", "name:D"]);
    expect(state.lastProxyAclPositionQuery).toMatchObject({ id: "0", toId: "1" });
    expect(state.lastProxyAclPositionQuery).not.toHaveProperty("beforeRuleId");
  });

  it("throws when the position POST succeeds but order does not change", async () => {
    const state = createMockState();
    state.proxyAclRules = starting.map((rule) => ({ ...rule }));
    state.proxyAclPositionNoop = true;
    const client = makeClient(state);
    await expect(client.network.moveProxyAclRule({ id: 0, toId: 2 })).rejects.toBeInstanceOf(IbossVerifyError);
    expect(state.proxyAclRules.map((rule) => rule.name)).toEqual(["A", "B", "C", "D"]);
  });

  it("does not POST when the rule is already in the requested slot", async () => {
    const state = createMockState();
    state.proxyAclRules = starting.map((rule) => ({ ...rule }));
    const client = makeClient(state);
    const result = await client.network.moveProxyAclRule({ id: 1, toId: 1 });
    expect(result.moved).toBe(false);
    expect(result.attempts).toBe(0);
    expect(state.requests.some((line) => line.includes("rule/position"))).toBe(false);
  });

  it("re-GETs after a dropped connection and does not POST twice when the move stuck", async () => {
    const state = createMockState();
    state.proxyAclRules = starting.map((rule) => ({ ...rule }));
    state.proxyAclDropNextPosition = 1;
    const client = makeClient(state);
    const result = await client.network.moveProxyAclRule({ id: 1, toId: 3 });
    expect(result.moved).toBe(true);
    expect(result.attempts).toBe(1);
    expect(result.orderAfter).toEqual(["name:A", "name:C", "name:D", "name:B"]);
    expect(
      state.requests.filter((line) => line === `POST ${GATEWAY_HOST}/json/network/proxy/acl/rule/position`),
    ).toHaveLength(1);
  });
});
