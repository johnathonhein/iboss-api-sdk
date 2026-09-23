/**
 * Network-side settings (gateway tier) spanning three console sections:
 *
 *  - Network → Proxy & Caching: proxy settings, proxy logging
 *    (docs/api/proxy-and-caching.md)
 *  - Secure Access Policies → Private Access (ZTNA): routed peers, DHCP
 *    gateway/NAT (docs/api/private-access-policies.md)
 *  - Connect Devices & Locations → Connector Settings: per-group connector
 *    settings incl. security keys (docs/api/connector-policies.md)
 *
 * Gotcha: creating a routed peer does NOT return its uuid. Re-list peers and
 * match on your locationUuids/name to find it (createPeerAndFind does this).
 */
import { IbossNetworkError, IbossVerifyError } from "../client/errors.js";
import { SubClient, type EntriesResponse, type SuccessResponse } from "./base.js";
import {
  moveProxyAclRules,
  normalizeProxyAclRules,
  proxyAclOrderKeys,
  readProxyAclPositionEcho,
  resolveProxyAclDestination,
  sameProxyAclOrder,
  type ProxyAclRuleRef,
} from "./proxyAcl.js";

export interface ZtnaPeer {
  uuid?: string;
  name?: string;
  aclIpSubnetList?: string;
  locationUuids?: string;
  locationBased?: number;
  [key: string]: unknown;
}

export interface MoveProxyAclRuleParams {
  /** Absolute ACL-map index from `listProxyAclRules` / GET `…/proxy/acl/rule`. */
  id: number;
  /**
   * Move `id` into the slot of this absolute index. Gateway query `toId`.
   * Pass exactly one of `toId`, `beforeRuleId`, `afterRuleId`.
   */
  toId?: number;
  /**
   * SDK alias: place `id` immediately before this absolute index.
   * Resolved to `toId` client-side. Gateway does not accept this name (DEVELOP-34959).
   */
  beforeRuleId?: number;
  /** SDK alias: place `id` immediately after this absolute index. */
  afterRuleId?: number;
  /** ACL entry type. Default 2, the map Braxton reads. */
  entryType?: number;
  signal?: AbortSignal;
}

export interface MoveProxyAclRuleResult {
  fromIndex: number;
  toIndex: number;
  moved: boolean;
  orderBefore: string[];
  orderAfter: string[];
  /**
   * From the position response when Gateway sends `orderRevision` (DEVELOP-34959).
   * Null when the field is absent, or when no POST was sent.
   */
  orderRevision: number | null;
  /** From the position response when Gateway sends `resultingIndex`. */
  resultingIndex?: number;
  /**
   * Raw position response. It may claim success when `moved` is false — the
   * SDK does not trust it. Undefined when no POST was sent (already in place).
   */
  response?: Record<string, unknown>;
  /** Position POSTs sent. A connection drop re-GETs before a second attempt. */
  attempts: number;
}

const PROXY_ACL_RULE_PATH = "/json/network/proxy/acl/rule";
const PROXY_ACL_POSITION_PATH = "/json/network/proxy/acl/rule/position";

export class NetworkApi extends SubClient {
  async updateProxySettings(settings: Record<string, unknown>): Promise<SuccessResponse> {
    return this.request("gateway", "POST", "/json/network/proxy/settings", { body: settings });
  }

  /**
   * Proxy error/access logging toggles, e.g.
   * { logProxyAccessDeniedErrors: false, logProxyAllOtherErrors: true,
   *   logProxyDnsConnectionFailures: true }.
   */
  async updateProxyLogging(settings: Record<string, boolean>): Promise<SuccessResponse> {
    return this.request("gateway", "POST", "/json/preferences/reportSettings/changeProxyLogging", {
      body: settings,
    });
  }

  /**
   * Ordered proxy ACL rules. `entryType` defaults to 2.
   * `id` / `toId` on `moveProxyAclRule` are absolute indices from this list.
   */
  async listProxyAclRules(entryType = 2, signal?: AbortSignal): Promise<ProxyAclRuleRef[]> {
    const payload = await this.request("gateway", "GET", PROXY_ACL_RULE_PATH, {
      query: { entryType },
      signal,
    });
    return normalizeProxyAclRules(payload);
  }

  /**
   * Move one proxy ACL rule and verify the order with a follow-up GET.
   *
   * Gateway `POST …/proxy/acl/rule/position` can return success while the
   * order is unchanged (DEVELOP-34959). This method throws `IbossVerifyError`
   * on that silent no-op. It does not trust the POST body.
   *
   * The position POST is not idempotent. Transport retries inside the request
   * layer are disabled (`maxAttempts: 1`). On a dropped connection the SDK
   * re-GETs and only POSTs again when the order did not already change.
   *
   * `beforeRuleId` / `afterRuleId` are client-side aliases. The wire call is
   * still `id` + `toId`. `orderRevision` is copied from the position body when
   * present and stays null on older nodes. `moved` on the SDK result follows
   * the re-GET, not the POST `moved` flag.
   */
  async moveProxyAclRule(params: MoveProxyAclRuleParams): Promise<MoveProxyAclRuleResult> {
    const entryType = params.entryType ?? 2;
    const before = await this.listProxyAclRules(entryType, params.signal);
    const { fromIndex, toIndex } = resolveProxyAclDestination(before, params);
    const orderBefore = proxyAclOrderKeys(before);
    if (fromIndex === toIndex) {
      return {
        fromIndex,
        toIndex,
        moved: false,
        orderBefore,
        orderAfter: orderBefore,
        orderRevision: null,
        attempts: 0,
      };
    }
    const expected = proxyAclOrderKeys(moveProxyAclRules(before, fromIndex, toIndex));

    let attempts = 0;
    let response: Record<string, unknown> | undefined;
    let pendingNetworkError: IbossNetworkError | undefined;

    for (let tryNo = 0; tryNo < 2; tryNo++) {
      const current = tryNo === 0 ? before : await this.listProxyAclRules(entryType, params.signal);
      const currentOrder = proxyAclOrderKeys(current);
      if (sameProxyAclOrder(currentOrder, expected)) {
        const echo = readProxyAclPositionEcho(response);
        return {
          fromIndex,
          toIndex,
          moved: true,
          orderBefore,
          orderAfter: currentOrder,
          orderRevision: echo.orderRevision,
          ...(echo.resultingIndex !== undefined ? { resultingIndex: echo.resultingIndex } : {}),
          response,
          attempts,
        };
      }
      try {
        attempts += 1;
        response = await this.request<Record<string, unknown>>("gateway", "POST", PROXY_ACL_POSITION_PATH, {
          query: { id: fromIndex, toId: toIndex },
          retry: { maxAttempts: 1 },
          signal: params.signal,
        });
        pendingNetworkError = undefined;
        break;
      } catch (error) {
        if (!(error instanceof IbossNetworkError)) throw error;
        pendingNetworkError = error;
      }
    }

    if (pendingNetworkError) {
      const recovered = await this.listProxyAclRules(entryType, params.signal);
      const recoveredOrder = proxyAclOrderKeys(recovered);
      if (sameProxyAclOrder(recoveredOrder, expected)) {
        const echo = readProxyAclPositionEcho(response);
        return {
          fromIndex,
          toIndex,
          moved: true,
          orderBefore,
          orderAfter: recoveredOrder,
          orderRevision: echo.orderRevision,
          ...(echo.resultingIndex !== undefined ? { resultingIndex: echo.resultingIndex } : {}),
          response,
          attempts,
        };
      }
      throw pendingNetworkError;
    }

    const after = await this.listProxyAclRules(entryType, params.signal);
    const orderAfter = proxyAclOrderKeys(after);
    const echo = readProxyAclPositionEcho(response);
    if (!sameProxyAclOrder(orderAfter, expected)) {
      throw new IbossVerifyError(
        `POST /json/network/proxy/acl/rule/position reported success but rule order did not change ` +
          `(id ${fromIndex} → toId ${toIndex}). Gateway can return success on a silent no-op ` +
          `(DEVELOP-34959). Do not trust the position response; compare GET order before and after.`,
        {
          failures: [
            `order stayed ${orderAfter.join(" | ") || "(empty)"}; expected ${expected.join(" | ")}`,
          ],
          actual: {
            fromIndex,
            toIndex,
            orderBefore,
            orderAfter,
            response: response ?? null,
            orderRevision: echo.orderRevision,
          },
        },
      );
    }
    return {
      fromIndex,
      toIndex,
      moved: true,
      orderBefore,
      orderAfter,
      orderRevision: echo.orderRevision,
      ...(echo.resultingIndex !== undefined ? { resultingIndex: echo.resultingIndex } : {}),
      response,
      attempts,
    };
  }

  // --- ZTNA routed peers --------------------------------------------------

  async listPeers(): Promise<ZtnaPeer[]> {
    const result = await this.request<EntriesResponse<ZtnaPeer> | ZtnaPeer[]>(
      "gateway",
      "GET",
      "/json/network/mobileClients/peer",
    );
    return Array.isArray(result) ? result : (result?.entries ?? []);
  }

  /** Create a routed peer. The response has no uuid — see createPeerAndFind. */
  async createPeer(peer: ZtnaPeer): Promise<SuccessResponse> {
    return this.request("gateway", "PUT", "/json/network/mobileClients/peer", { body: peer });
  }

  /**
   * Create a routed peer, then poll the peer list until it appears (location
   * UUID propagation can take a few seconds) and return it with its uuid.
   */
  async createPeerAndFind(
    peer: ZtnaPeer & { name: string },
    opts: { attempts?: number; delayMs?: number } = {},
  ): Promise<ZtnaPeer> {
    await this.createPeer(peer);
    const attempts = opts.attempts ?? 15;
    const delayMs = opts.delayMs ?? 2000;
    for (let i = 0; i < attempts; i++) {
      const peers = await this.listPeers();
      const match = peers.find(
        (p) =>
          (peer.locationUuids && p.locationUuids === peer.locationUuids) ||
          p.name === peer.name,
      );
      if (match?.uuid) return match;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
    throw new Error(`Routed peer "${peer.name}" was created but never appeared in the peer list.`);
  }

  async deletePeer(uuid: string): Promise<SuccessResponse> {
    return this.request("gateway", "DELETE", "/json/network/mobileClients/peer", {
      query: { uuid },
    });
  }

  // --- Mobile client / connector group settings ----------------------------

  /** Group settings including the connector security key. */
  async getMobileClientSettings(policyGroup: number): Promise<Record<string, unknown>> {
    return this.request("gateway", "GET", "/json/network/mobileClients/settings", {
      query: { currentPolicyBeingEdited: policyGroup },
    });
  }

  async updateMobileClientSettings(
    policyGroup: number,
    settings: Record<string, unknown>,
  ): Promise<SuccessResponse> {
    return this.request("gateway", "POST", "/json/network/mobileClients/settings", {
      query: { currentPolicyBeingEdited: policyGroup },
      body: settings,
    });
  }

  /** ZTNA flow DHCP gateway / NAT configuration. */
  async updateZtnaFlowDhcpGateway(settings: Record<string, unknown>): Promise<SuccessResponse> {
    return this.request("gateway", "POST", "/json/network/mobileClients/ztnaFlowDhcpGateway", {
      body: settings,
    });
  }
}
