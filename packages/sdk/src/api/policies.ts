/**
 * Policy management (gateway tier). Four console policy types share these
 * wire endpoints (/json/controls/policyLayers):
 *
 *  - Resource Policies (SaaS & Internet Access Policies):
 *    isZeroTrustResourcePolicy: 1 — docs/api/resource-policies.md
 *  - Private Access routed policies (ZTNA): resource-policy shape +
 *    ztnaFlowPeerIds — docs/api/private-access-policies.md
 *  - Policy Layers (overlays linked to default policy groups):
 *    isZeroTrustResourcePolicy: 0 — docs/api/policy-layers.md
 *  - Connector Policies (iboss agent config): customType 12 —
 *    docs/api/connector-policies.md
 *
 * CRITICAL GOTCHA — policy creation is a TWO-STEP process:
 *   1. PUT  /json/controls/policyLayers          → returns customCategoryId + customCategoryNumber
 *   2. POST /json/controls/policyLayers/settings → applies the full settings payload
 * createLayer() wraps both steps; the raw steps are exposed as
 * createLayerStructure() and updateLayerSettings() for advanced use.
 *
 * Resource Policies MUST include dlpPolicyMethod: 2 in every settings payload
 * (createLayer adds it when isZeroTrustResourcePolicy: 1).
 *
 * Partial settings updates: `patchResourcePolicySettings` GETs the current
 * blob, deep-merges the caller patch, and POSTs the full object.
 * `updateLayerSettings` is still a caller-supplied full replace — a sparse
 * body can wipe omitted fields. See docs/api/resource-policies.md.
 */
import { IbossVerifyError } from "../client/errors.js";
import { SubClient, type EntriesResponse, type SuccessResponse } from "./base.js";
import {
  emptyCategoriesBitmap,
  generateBypassSslMitmFields,
  generateCategoryFields,
  generatePriorityFields,
} from "./policyFields.js";
import {
  collectVerifyFailures,
  mergeResourcePolicySettings,
  summarizeResourcePolicySettings,
  type ResourcePolicyPatch,
  type ResourcePolicySettingsSummary,
} from "./resourcePolicySettings.js";

export {
  emptyCategoriesBitmap,
  generateBypassSslMitmFields,
  generateCategoryFields,
  generatePriorityFields,
  POLICY_FIELD_FAMILY_MAX,
} from "./policyFields.js";
export type { ResourcePolicyPatch, ResourcePolicySettingsSummary } from "./resourcePolicySettings.js";

export type PolicyLayerType = "blocklist" | "allowlist" | "categories";

const CUSTOM_TYPE: Record<PolicyLayerType, string> = {
  blocklist: "e_custom_category_type_blacklist",
  allowlist: "e_custom_category_type_allowlist",
  categories: "e_custom_category_type_categories",
};

export interface PolicyLayer {
  customCategoryId: number;
  customCategoryNumber: number;
  customCategoryName: string;
  customType?: string | number;
  policyEnabled?: number;
  isZeroTrustResourcePolicy?: number;
  isZtnaPrivateAccessCategory?: number;
  placeAtPosition?: number;
  [key: string]: unknown;
}

export interface CreateLayerResult {
  customCategoryId: number;
  customCategoryNumber: number;
  id?: number;
  [key: string]: unknown;
}

export interface PolicyLayerUrl {
  url: string;
  [key: string]: unknown;
}

export class PoliciesApi extends SubClient {
  /**
   * List policy layers via the paginated `/all` endpoint (the platform's
   * actual listing mechanism — there is no single-page "all" response).
   *
   * Filters: `isZeroTrustLayer` -1 = both, 0 = gateway layers only, 1 =
   * resource policies only; `typeFilter` -1 = all types.
   */
  async listLayers(opts?: {
    isZeroTrustLayer?: -1 | 0 | 1;
    typeFilter?: number;
  }): Promise<PolicyLayer[]> {
    const pageSize = 100;
    const all: PolicyLayer[] = [];
    for (let currentRow = 0; ; currentRow += pageSize) {
      const result = await this.request<EntriesResponse<PolicyLayer>>(
        "gateway",
        "GET",
        "/json/controls/policyLayers/all",
        {
          query: {
            isZeroTrustLayer: opts?.isZeroTrustLayer ?? -1,
            typeFilter: opts?.typeFilter ?? -1,
            currentRow,
            maxItems: pageSize,
            // Empty filter params are required by the endpoint.
            nameFilter: "",
            domainFilter: "",
            groupNameFilter: "",
            groupExcludeNameFilter: "",
            ipInclusionFilter: "",
            ipExclusionFilter: "",
            notesFilter: "",
            portFilter: "",
            usernameFilter: "",
          },
        },
      );
      const entries = result?.entries ?? [];
      all.push(...entries);
      if (entries.length < pageSize) break;
    }
    return all;
  }

  /** Read the full settings of one policy layer. */
  async getLayerSettings(
    customCategoryId: number,
    opts?: { signal?: AbortSignal },
  ): Promise<Record<string, unknown>> {
    return this.request("gateway", "GET", "/json/controls/policyLayers/settings", {
      query: { customCategoryId },
      signal: opts?.signal,
    });
  }

  /**
   * Step 1 only: create the policy layer structure. Most callers should use
   * createLayer() which also applies settings.
   */
  async createLayerStructure(params: {
    name: string;
    type: PolicyLayerType;
    /** Set 1 to create a Zero Trust resource policy instead of a gateway layer. */
    isZeroTrustResourcePolicy?: 0 | 1;
    enterpriseOwned?: 0 | 1;
    placeAtPosition?: number;
    extra?: Record<string, unknown>;
  }): Promise<CreateLayerResult> {
    return this.request("gateway", "PUT", "/json/controls/policyLayers", {
      body: {
        customCategoryName: params.name,
        customType: CUSTOM_TYPE[params.type],
        isZtnaPrivateAccessCategory: 0,
        isZeroTrustResourcePolicy: params.isZeroTrustResourcePolicy ?? 0,
        ...(params.enterpriseOwned !== undefined ? { enterpriseOwned: params.enterpriseOwned } : {}),
        placeAtPosition: params.placeAtPosition ?? 0,
        ...params.extra,
      },
    });
  }

  /** Step 2 only: apply a full settings payload to an existing layer. */
  async updateLayerSettings(settings: {
    customCategoryId: number;
    customCategoryNumber: number;
    customCategoryName: string;
    [key: string]: unknown;
  }): Promise<SuccessResponse> {
    return this.request("gateway", "POST", "/json/controls/policyLayers/settings", {
      body: settings,
    });
  }

  /**
   * Create a policy layer and apply its settings (the two-step dance) in one
   * call. Returns the ids from step 1.
   *
   * ```ts
   * const layer = await client.policies.createLayer({
   *   name: "Global Blocklist",
   *   type: "blocklist",
   *   settings: { policyAction: 0, linkPolicyToAllSubjects: 1 },
   * });
   * await client.policies.addLayerUrl(layer.customCategoryId, "example.com");
   * ```
   */
  async createLayer(params: {
    name: string;
    type: PolicyLayerType;
    isZeroTrustResourcePolicy?: 0 | 1;
    enterpriseOwned?: 0 | 1;
    placeAtPosition?: number;
    /** Merged over sensible defaults (enabled, all-users, default category fields). */
    settings?: Record<string, unknown>;
  }): Promise<CreateLayerResult> {
    const created = await this.createLayerStructure(params);

    const isResourcePolicy = params.isZeroTrustResourcePolicy === 1;
    const settings: Record<string, unknown> = {
      customCategoryId: created.customCategoryId,
      customCategoryNumber: created.customCategoryNumber,
      customCategoryName: params.name,
      policyEnabled: 1,
      linkPolicyToAllSubjects: 1,
      ...generateCategoryFields(),
      ...generatePriorityFields(),
      ...generateBypassSslMitmFields(),
      categories: emptyCategoriesBitmap(),
      // Mandatory for resource policies; harmless default otherwise omitted.
      ...(isResourcePolicy ? { dlpPolicyMethod: 2 } : {}),
      ...params.settings,
    };
    await this.updateLayerSettings(settings as Parameters<PoliciesApi["updateLayerSettings"]>[0]);
    return created;
  }

  async deleteLayer(customCategoryId: number): Promise<SuccessResponse> {
    return this.request("gateway", "DELETE", "/json/controls/policyLayers", {
      query: { customCategoryId },
    });
  }

  /** URLs/domains attached to a blocklist/allowlist layer. */
  async getLayerUrls(customCategoryId: number): Promise<PolicyLayerUrl[]> {
    const result = await this.request<EntriesResponse<PolicyLayerUrl> | PolicyLayerUrl[]>(
      "gateway",
      "GET",
      "/json/controls/policyLayers/urls",
      { query: { customCategoryId } },
    );
    return Array.isArray(result) ? result : (result?.entries ?? []);
  }

  /** Add one URL/domain to a layer's list. */
  async addLayerUrl(
    customCategoryId: number,
    url: string,
    extra?: Record<string, unknown>,
  ): Promise<SuccessResponse> {
    return this.request("gateway", "PUT", "/json/controls/policyLayers/urls", {
      query: { customCategoryId },
      body: { url, ...extra },
    });
  }

  /** Remove one URL/domain from a layer's list. */
  async removeLayerUrl(customCategoryId: number, url: string): Promise<SuccessResponse> {
    return this.request("gateway", "DELETE", "/json/controls/policyLayers/urls", {
      query: { customCategoryId, url },
    });
  }

  /**
   * Bulk-import URLs into a layer in one request (the console's import
   * mechanism) — much faster than addLayerUrl in a loop for large lists.
   */
  async importLayerUrls(params: {
    customCategoryId: number;
    customCategoryNumber: number;
    urls: string[];
    /** Merged into every imported entry (e.g. { isRegex: "1" }). */
    entryDefaults?: Record<string, unknown>;
  }): Promise<SuccessResponse> {
    return this.request("gateway", "PUT", "/bulk/controls/policyLayers/urls", {
      body: {
        importList: params.urls.map((url) => ({
          url,
          applyKeyword: "0",
          isRegex: "0",
          note: "",
          timedUrl: "",
          doMalwareScan: 1,
          doDlpScan: 1,
          doFileChecks: 1,
          overrideZeroTrust: 0,
          applyKeywordAndSafeSearch: "0",
          ...params.entryDefaults,
        })),
        defaults: {
          customCategoryId: params.customCategoryId,
          customCategoryNumber: params.customCategoryNumber,
        },
      },
    });
  }

  // --- Zero Trust resource policies -------------------------------------

  async listResourcePolicies(): Promise<Record<string, unknown>[]> {
    const result = await this.request<EntriesResponse<Record<string, unknown>> | Record<string, unknown>[]>(
      "gateway",
      "GET",
      "/json/controls/resourcePolicies",
    );
    return Array.isArray(result) ? result : (result?.entries ?? []);
  }

  /** Resources currently associated with a resource policy. */
  async getResourcePolicyResources(customCategoryId: number): Promise<Record<string, unknown>[]> {
    const result = await this.request<EntriesResponse<Record<string, unknown>> | Record<string, unknown>[]>(
      "gateway",
      "GET",
      "/json/controls/resourcePolicy/resources",
      { query: { customCategoryId } },
    );
    return Array.isArray(result) ? result : (result?.entries ?? []);
  }

  /**
   * Associate enterprise resource UUIDs with a resource policy.
   *
   * Wire shape (matches the platform console): PUT with the policy's
   * customCategoryId as a query param and { customCategoryNumber,
   * resourceIds } as the body — note both ids are required and the body
   * field is `resourceIds`.
   */
  async associateResources(params: {
    customCategoryId: number;
    customCategoryNumber: number;
    resourceIds: string[];
  }): Promise<SuccessResponse> {
    return this.request("gateway", "PUT", "/json/controls/resourcePolicy/resources", {
      query: { customCategoryId: params.customCategoryId },
      body: {
        customCategoryNumber: params.customCategoryNumber,
        resourceIds: params.resourceIds,
      },
    });
  }

  /**
   * Dedicated Resource Policy read (DEVELOP-34914). Same wire path as
   * `getLayerSettings`: `GET /json/controls/policyLayers/settings?customCategoryId=`.
   *
   * Default `view` is `"full"` (the GET blob, including catN families).
   * `view: "summary"` returns identity and a few agent-facing flags and
   * leaves the bitmap and field families out of the result.
   */
  async getResourcePolicySettings(
    customCategoryId: number,
    opts: { view: "summary"; signal?: AbortSignal },
  ): Promise<ResourcePolicySettingsSummary>;
  async getResourcePolicySettings(
    customCategoryId: number,
    opts?: { view?: "full"; signal?: AbortSignal },
  ): Promise<Record<string, unknown>>;
  async getResourcePolicySettings(
    customCategoryId: number,
    opts?: { view?: "summary" | "full"; signal?: AbortSignal },
  ): Promise<ResourcePolicySettingsSummary | Record<string, unknown>> {
    const full = await this.getLayerSettings(customCategoryId, { signal: opts?.signal });
    return opts?.view === "summary" ? summarizeResourcePolicySettings(full) : full;
  }

  /**
   * SDK-only UPDATE (DEVELOP-34914). This is not an HTTP PATCH and there
   * is no native Gateway merge on this endpoint.
   *
   * 1. GET `/json/controls/policyLayers/settings?customCategoryId=`
   * 2. Deep-merge `patch` onto that blob. Omitted keys keep prior values,
   *    including every catN / prioN / bypassSslMitmN member.
   * 3. Fill family members the GET lacked so the POST cannot rely on
   *    Gateway defaults for missing fields (DEVELOP-34251 / DEVELOP-32482).
   * 4. POST the full merged object to `/json/controls/policyLayers/settings`.
   * 5. GET again and return that blob. Throw `IbossVerifyError` when a
   *    patch field (or a `dlpPolicyMethod` this helper had to fill) did not
   *    persist. POST success and an empty `saveIgnoredEntries` are not
   *    persistence. The returned object is the confirming GET, so a family
   *    value that did not round-trip is visible there.
   *
   * Concurrent writers: another client can change the policy between steps
   * 1 and 4. Last POST wins. That TOCTOU window is accepted for agent v1
   * (native Gateway PATCH is DEVELOP-34921 and is out of scope here).
   *
   * `updateLayerSettings` stays a caller-supplied full replace. Passing it
   * a sparse body can wipe omitted fields; use this method for patches.
   */
  async patchResourcePolicySettings(
    customCategoryId: number,
    patch: ResourcePolicyPatch,
    opts: { view: "summary"; signal?: AbortSignal },
  ): Promise<ResourcePolicySettingsSummary>;
  async patchResourcePolicySettings(
    customCategoryId: number,
    patch: ResourcePolicyPatch,
    opts?: { view?: "full"; signal?: AbortSignal },
  ): Promise<Record<string, unknown>>;
  async patchResourcePolicySettings(
    customCategoryId: number,
    patch: ResourcePolicyPatch,
    opts?: { view?: "summary" | "full"; signal?: AbortSignal },
  ): Promise<ResourcePolicySettingsSummary | Record<string, unknown>> {
    const current = await this.getLayerSettings(customCategoryId, { signal: opts?.signal });
    const { next, verify } = mergeResourcePolicySettings(current, patch);

    await this.request("gateway", "POST", "/json/controls/policyLayers/settings", {
      body: next,
      signal: opts?.signal,
    });

    const persisted = await this.getLayerSettings(customCategoryId, { signal: opts?.signal });
    const failures = collectVerifyFailures(persisted, verify);
    if (failures.length > 0) {
      throw new IbossVerifyError(
        `Resource policy ${customCategoryId} settings POST reported success but GET did not ` +
          `persist: ${failures.join("; ")}. POST success and an empty saveIgnoredEntries are not persistence.`,
        { customCategoryId, failures, actual: persisted },
      );
    }
    return opts?.view === "summary" ? summarizeResourcePolicySettings(persisted) : persisted;
  }

  /**
   * One-shot Resource Policy create (DEVELOP-34914).
   *
   * Runs the existing two-step create (`createLayer` with
   * `isZeroTrustResourcePolicy: 1`), then GETs
   * `/json/controls/policyLayers/settings` and returns that effective
   * settings object. `createLayer` is unchanged and still returns ids only.
   */
  async createResourcePolicy(params: {
    name: string;
    type: PolicyLayerType;
    enterpriseOwned?: 0 | 1;
    placeAtPosition?: number;
    /** Merged over createLayer defaults (families, dlpPolicyMethod: 2, enabled). */
    settings?: Record<string, unknown>;
    signal?: AbortSignal;
  }): Promise<Record<string, unknown>> {
    const created = await this.createLayer({
      name: params.name,
      type: params.type,
      isZeroTrustResourcePolicy: 1,
      enterpriseOwned: params.enterpriseOwned,
      placeAtPosition: params.placeAtPosition,
      settings: params.settings,
    });
    return this.getLayerSettings(created.customCategoryId, { signal: params.signal });
  }
}
