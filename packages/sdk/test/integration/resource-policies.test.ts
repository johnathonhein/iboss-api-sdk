import { describe, expect, it } from "vitest";
import { IbossClient } from "../../src/client/IbossClient.js";
import { IbossVerifyError } from "../../src/client/errors.js";
import { hasFieldFamily, POLICY_FIELD_FAMILY_MAX } from "../../src/api/policyFields.js";
import type { ResourcePolicySettingsSummary } from "../../src/api/resourcePolicySettings.js";
import { CLOUD_HOST, MOCK_API_KEY } from "../mock-server/fixtures.js";
import { createMockState, mockFetch } from "../mock-server/mockIboss.js";

function makeClient(state = createMockState()) {
  return new IbossClient({
    domain: CLOUD_HOST,
    credentials: { apiKey: MOCK_API_KEY },
    fetch: mockFetch(state),
  });
}

function settingsGets(state: ReturnType<typeof createMockState>): string[] {
  return state.requests.filter((line) => line.endsWith("/json/controls/policyLayers/settings") && line.startsWith("GET "));
}

describe("resource-policy patch UPDATE (DEVELOP-34914)", () => {
  it("GET → deep-merge → full POST keeps distinctive family and unrelated fields", async () => {
    const state = createMockState();
    const client = makeClient(state);
    const created = await client.policies.createLayer({
      name: "Approved Apps",
      type: "allowlist",
      isZeroTrustResourcePolicy: 1,
    });

    const bitmap = "1".repeat(400);
    const stored = state.settingsById[created.customCategoryId]!;
    stored.cat7 = 9;
    stored.prio3 = 4;
    stored.bypassSslMitm10 = 1;
    stored.showPACUrl = 1;
    stored.aiRiskMonitoringMessage = "keep me";
    stored.categories = bitmap;

    const got = await client.policies.patchResourcePolicySettings(created.customCategoryId, {
      aiRiskEnabled: 1,
    });

    expect(got.aiRiskEnabled).toBe(1);
    expect(got.cat7).toBe(9);
    expect(got.prio3).toBe(4);
    expect(got.bypassSslMitm10).toBe(1);
    expect(got.showPACUrl).toBe(1);
    expect(got.aiRiskMonitoringMessage).toBe("keep me");
    expect(got.categories).toBe(bitmap);
    expect(got.dlpPolicyMethod).toBe(2);

    const posted = state.layerSettings.at(-1)!;
    expect(posted.aiRiskEnabled).toBe(1);
    expect(posted.cat7).toBe(9);
    expect(posted.prio3).toBe(4);
    expect(posted.bypassSslMitm10).toBe(1);
    expect(posted.showPACUrl).toBe(1);
    expect(posted.aiRiskMonitoringMessage).toBe("keep me");
    expect(posted.categories).toBe(bitmap);
    expect(hasFieldFamily(posted, "cat")).toBe(true);
    expect(hasFieldFamily(posted, "prio")).toBe(true);
    expect(hasFieldFamily(posted, "bypassSslMitm")).toBe(true);
    for (let i = 0; i <= POLICY_FIELD_FAMILY_MAX; i++) {
      expect(posted[`cat${i}`], `posted cat${i}`).toBeDefined();
      expect(posted[`prio${i}`], `posted prio${i}`).toBeDefined();
      expect(posted[`bypassSslMitm${i}`], `posted bypassSslMitm${i}`).toBeDefined();
    }

    expect(state.requests.some((line) => line.startsWith("PATCH "))).toBe(false);
    expect(state.requests.some((line) => line.includes("/settings/patch"))).toBe(false);
    expect(settingsGets(state).length).toBeGreaterThanOrEqual(2);
  });

  it("a sparse settings POST without merge defaults families and drops prior fields", async () => {
    const state = createMockState();
    const client = makeClient(state);
    const created = await client.policies.createLayer({
      name: "Approved Apps",
      type: "allowlist",
      isZeroTrustResourcePolicy: 1,
    });

    const bitmap = "1".repeat(400);
    const stored = state.settingsById[created.customCategoryId]!;
    stored.cat7 = 9;
    stored.prio3 = 4;
    stored.bypassSslMitm10 = 1;
    stored.showPACUrl = 1;
    stored.aiRiskMonitoringMessage = "keep me";
    stored.categories = bitmap;

    await client.policies.updateLayerSettings({
      customCategoryId: created.customCategoryId,
      customCategoryNumber: created.customCategoryNumber,
      customCategoryName: "Approved Apps",
      aiRiskEnabled: 1,
    });

    const posted = state.layerSettings.at(-1)!;
    expect(posted.cat7).toBeUndefined();
    expect(posted.prio3).toBeUndefined();
    expect(posted.bypassSslMitm10).toBeUndefined();
    expect(posted.showPACUrl).toBeUndefined();
    expect(posted.categories).toBeUndefined();

    const got = await client.policies.getLayerSettings(created.customCategoryId);
    expect(got.aiRiskEnabled).toBe(1);
    expect(got.cat7).toBe(3);
    expect(got.prio3).toBe(0);
    expect(got.bypassSslMitm10).toBe(0);
    expect(got.categories).toBe("0".repeat(400));
    expect(got.showPACUrl).not.toBe(1);
    expect(got.aiRiskMonitoringMessage).not.toBe("keep me");
    expect(hasFieldFamily(got, "cat")).toBe(true);
    expect(hasFieldFamily(got, "prio")).toBe(true);
    expect(hasFieldFamily(got, "bypassSslMitm")).toBe(true);
  });

  it("getResourcePolicySettings reads GET policyLayers/settings", async () => {
    const state = createMockState();
    const client = makeClient(state);
    const created = await client.policies.createResourcePolicy({
      name: "Approved Apps",
      type: "allowlist",
      settings: { policyAction: 1, cat7: 9 },
    });

    expect(created.customCategoryName).toBe("Approved Apps");
    expect(created.policyAction).toBe(1);
    expect(created.cat7).toBe(9);
    expect(created.cat110).toBe(3);
    expect(created.dlpPolicyMethod).toBe(2);
    expect(created.isZeroTrustResourcePolicy).toBe(1);
    expect(created.customCategoryId).toBeGreaterThan(0);
    expect(settingsGets(state)).toHaveLength(1);

    const full = await client.policies.getResourcePolicySettings(created.customCategoryId as number);
    expect(full.cat7).toBe(9);
    expect(full.policyAction).toBe(1);

    const summary = (await client.policies.getResourcePolicySettings(created.customCategoryId as number, {
      view: "summary",
    })) as ResourcePolicySettingsSummary;
    expect(summary.kind).toBe("resource");
    expect(summary.customCategoryId).toBe(created.customCategoryId);
    expect(summary.dlpPolicyMethod).toBe(2);
    expect(summary.enabled).toBe(true);
    expect("cat0" in summary).toBe(false);
    expect("categories" in summary).toBe(false);
  });

  it("throws IbossVerifyError when POST succeeds but a sent field does not persist", async () => {
    const state = createMockState();
    const client = makeClient(state);
    const created = await client.policies.createLayer({
      name: "Approved Apps",
      type: "allowlist",
      isZeroTrustResourcePolicy: 1,
    });
    state.dropPostedKeys = ["aiRiskEnabled"];

    await expect(
      client.policies.patchResourcePolicySettings(created.customCategoryId, { aiRiskEnabled: 1 }),
    ).rejects.toBeInstanceOf(IbossVerifyError);
  });
});
