/**
 * Proxy ACL rule order helpers (DEVELOP-34959).
 *
 * `POST /json/network/proxy/acl/rule/position?id=&toId=` can return success
 * while canonical order does not change. These helpers compute the expected
 * order from the before-GET so the client can detect that silent no-op.
 *
 * `id` / `toId` are absolute ACL-map indices from
 * `GET /json/network/proxy/acl/rule?entryType=2` (default entry type 2).
 * Each rule's index is `index`, else numeric `id`, else its position in the
 * returned list. Stable identity for the before/after compare is `ruleId`,
 * `uuid`, or `name` — rules that only carry a positional index cannot be
 * told apart after a renumber, and a move of those rules fails verification.
 *
 * Order model: remove the rule at `id`, then insert it at the list slot of
 * `toId` (standard list move). `beforeRuleId` / `afterRuleId` are SDK aliases
 * resolved to that `toId`. Gateway does not accept those names.
 * Live position responses include `{ fromIndex, toIndex, resultingIndex, moved, orderRevision }`
 * (DEVELOP-34959). `readProxyAclPositionEcho` surfaces that; a missing
 * `orderRevision` stays null so older nodes still work. GET order remains
 * the check for a silent success.
 */

export interface ProxyAclRuleRef {
  /** Absolute ACL-map index passed as `id` / `toId`. */
  index: number;
  /** Position in the GET list. */
  position: number;
  rule: Record<string, unknown>;
  /** Stable identity used to compare order before and after. */
  key: string;
}

export interface ProxyAclMoveTarget {
  id: number;
  toId?: number;
  beforeRuleId?: number;
  afterRuleId?: number;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function proxyAclAbsoluteIndex(rule: Record<string, unknown>, position: number): number {
  if (typeof rule.index === "number" && Number.isFinite(rule.index)) return rule.index;
  if (typeof rule.id === "number" && Number.isFinite(rule.id)) return rule.id;
  return position;
}

export function proxyAclRuleKey(rule: Record<string, unknown>, position: number): string {
  for (const field of ["ruleId", "uuid", "name"] as const) {
    const value = rule[field];
    if (typeof value === "string" && value.trim().length > 0) return `${field}:${value}`;
    if (typeof value === "number" && Number.isFinite(value)) return `${field}:${value}`;
  }
  const copy: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rule)) {
    if (key === "index" || key === "position" || key === "id") continue;
    copy[key] = value;
  }
  if (Object.keys(copy).length > 0) return `body:${JSON.stringify(copy)}`;
  return `pos:${position}`;
}

export function normalizeProxyAclRules(payload: unknown): ProxyAclRuleRef[] {
  let rows: unknown[] | undefined;
  if (Array.isArray(payload)) rows = payload;
  else if (isPlainObject(payload) && Array.isArray(payload.entries)) rows = payload.entries;
  else if (isPlainObject(payload) && Array.isArray(payload.rules)) rows = payload.rules;
  if (!rows) {
    throw new TypeError(
      "GET /json/network/proxy/acl/rule returned an unrecognized shape. Expected an array or { entries }.",
    );
  }
  return rows.filter(isPlainObject).map((rule, position) => ({
    index: proxyAclAbsoluteIndex(rule, position),
    position,
    rule,
    key: proxyAclRuleKey(rule, position),
  }));
}

export function proxyAclOrderKeys(rules: ProxyAclRuleRef[]): string[] {
  return rules.map((rule) => rule.key);
}

export function sameProxyAclOrder(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((key, i) => key === right[i]);
}

function findPos(rules: ProxyAclRuleRef[], index: number, label: string): number {
  const pos = rules.findIndex((rule) => rule.index === index);
  if (pos < 0) {
    throw new Error(
      `No proxy ACL rule at absolute index ${index} (${label}). ` +
        `Indices on this GET: ${rules.map((rule) => rule.index).join(", ") || "(empty)"}.`,
    );
  }
  return pos;
}

/**
 * Resolve `toId` / `beforeRuleId` / `afterRuleId` to the absolute destination
 * index the position endpoint expects.
 */
export function resolveProxyAclDestination(
  rules: ProxyAclRuleRef[],
  params: ProxyAclMoveTarget,
): { fromIndex: number; toIndex: number } {
  const specified = [params.toId, params.beforeRuleId, params.afterRuleId].filter(
    (value) => value !== undefined,
  );
  if (specified.length !== 1) {
    throw new TypeError(
      "moveProxyAclRule requires exactly one of toId, beforeRuleId, or afterRuleId. " +
        "beforeRuleId and afterRuleId are SDK aliases — Gateway only accepts id and toId (DEVELOP-34959).",
    );
  }
  if (!Number.isInteger(params.id)) {
    throw new TypeError("moveProxyAclRule id must be an integer absolute ACL-map index.");
  }
  const fromPos = findPos(rules, params.id, "id");

  if (params.toId !== undefined) {
    if (!Number.isInteger(params.toId)) {
      throw new TypeError("moveProxyAclRule toId must be an integer absolute ACL-map index.");
    }
    findPos(rules, params.toId, "toId");
    return { fromIndex: params.id, toIndex: params.toId };
  }

  if (params.beforeRuleId !== undefined) {
    if (!Number.isInteger(params.beforeRuleId)) {
      throw new TypeError("moveProxyAclRule beforeRuleId must be an integer absolute ACL-map index.");
    }
    const beforePos = findPos(rules, params.beforeRuleId, "beforeRuleId");
    if (beforePos === fromPos) {
      throw new TypeError("beforeRuleId is the rule being moved.");
    }
    const toPos = fromPos < beforePos ? beforePos - 1 : beforePos;
    return { fromIndex: params.id, toIndex: rules[toPos]!.index };
  }

  const afterPos = findPos(rules, params.afterRuleId!, "afterRuleId");
  if (afterPos === fromPos) {
    throw new TypeError("afterRuleId is the rule being moved.");
  }
  const toPos = fromPos < afterPos ? afterPos : afterPos + 1;
  if (toPos >= rules.length) {
    throw new Error(`afterRuleId ${params.afterRuleId} has no following slot to move into.`);
  }
  return { fromIndex: params.id, toIndex: rules[toPos]!.index };
}

/** Remove the rule at `fromIndex` and insert it at the slot of `toIndex`. */
export function moveProxyAclRules(
  rules: ProxyAclRuleRef[],
  fromIndex: number,
  toIndex: number,
): ProxyAclRuleRef[] {
  const fromPos = findPos(rules, fromIndex, "id");
  const toPos = findPos(rules, toIndex, "toId");
  const next = rules.slice();
  const [item] = next.splice(fromPos, 1);
  next.splice(toPos, 0, item!);
  return next;
}

export interface ProxyAclPositionEcho {
  fromIndex?: number;
  toIndex?: number;
  resultingIndex?: number;
  moved?: boolean;
  orderRevision: number | null;
}

function finiteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) {
    return Number(value);
  }
  return undefined;
}

/**
 * Read the live position body. `moved` is 0/1 on the wire. Absent
 * `orderRevision` stays null (pre-34959 nodes).
 */
export function readProxyAclPositionEcho(body: unknown): ProxyAclPositionEcho {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return { orderRevision: null };
  }
  const record = body as Record<string, unknown>;
  const movedRaw = record.moved;
  let moved: boolean | undefined;
  if (movedRaw === true || movedRaw === 1 || movedRaw === "1") moved = true;
  else if (movedRaw === false || movedRaw === 0 || movedRaw === "0") moved = false;
  return {
    fromIndex: finiteNumber(record.fromIndex),
    toIndex: finiteNumber(record.toIndex),
    resultingIndex: finiteNumber(record.resultingIndex),
    moved,
    orderRevision: finiteNumber(record.orderRevision) ?? null,
  };
}
