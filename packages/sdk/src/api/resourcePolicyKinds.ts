/**
 * Purpose-named Resource Policy kinds (DEVELOP-34958).
 *
 * Gateway `PUT /json/controls/policyLayers` used to reject numeric `customType`
 * 6 and 10 with 422 `Invalid entry type.` Live nodes accept those numerics
 * and echo `{ customType, enum, listKind }` (DEVELOP-34958). This module still
 * maps agent kinds to the enum strings and never emits the numerics, so the
 * same call works on older nodes.
 *
 * | kind         | enum                              | numeric (not sent) |
 * | ------------ | --------------------------------- | ------------------ |
 * | blocklist    | e_custom_category_type_blacklist  | 0                  |
 * | allowlist    | e_custom_category_type_allowlist  | 1                  |
 * | categories   | e_custom_category_type_categories | 3 (GET may say 13) |
 * | urlList      | e_custom_category_url_list        | 6                  |
 * | parent       | e_custom_category_type_parent     | 10                 |
 *
 * Live Gateway (DEVELOP-34958) accepts numeric 6/10 and echoes
 * `{ customType, enum, listKind }` on PUT. `createResourcePolicy({ kind })`
 * still sends the enum (works on older nodes). `wireKind.echoedByGateway`
 * is true only when that PUT body actually contains the echo.
 */
import { IbossPolicyTypeError } from "../client/errors.js";

export const RESOURCE_POLICY_KINDS = ["blocklist", "allowlist", "categories", "urlList", "parent"] as const;

export type ResourcePolicyKind = (typeof RESOURCE_POLICY_KINDS)[number];

export interface ResourcePolicyKindWire {
  kind: ResourcePolicyKind;
  /** Enum string safe to send on PUT today. */
  customType: string;
  /**
   * Numeric alias. Do not send until Gateway accepts it (DEVELOP-34958).
   * GET may already return this integer for policies created with the enum.
   */
  numeric: number;
  /** `createLayer` type, when this kind is also a policy-layer type. */
  layerType: "blocklist" | "allowlist" | "categories" | null;
}

export const RESOURCE_POLICY_KIND_WIRE: Record<ResourcePolicyKind, ResourcePolicyKindWire> = {
  blocklist: {
    kind: "blocklist",
    customType: "e_custom_category_type_blacklist",
    numeric: 0,
    layerType: "blocklist",
  },
  allowlist: {
    kind: "allowlist",
    customType: "e_custom_category_type_allowlist",
    numeric: 1,
    layerType: "allowlist",
  },
  categories: {
    kind: "categories",
    customType: "e_custom_category_type_categories",
    numeric: 3,
    layerType: "categories",
  },
  urlList: {
    kind: "urlList",
    customType: "e_custom_category_url_list",
    numeric: 6,
    layerType: null,
  },
  parent: {
    kind: "parent",
    customType: "e_custom_category_type_parent",
    numeric: 10,
    layerType: null,
  },
};

/**
 * Kind attached to a create result. `echoedByGateway` is false when the SDK
 * filled the fields itself (older nodes omit the echo).
 */
export interface ResourcePolicyWireKindAnnotation {
  kind: ResourcePolicyKind;
  customType: string;
  numeric: number;
  listKind: "resourcePolicy" | "policyLayer";
  echoedByGateway: boolean;
}

export function annotateResourcePolicyKind(wire: ResourcePolicyKindWire): ResourcePolicyWireKindAnnotation {
  return {
    kind: wire.kind,
    customType: wire.customType,
    numeric: wire.numeric,
    listKind: "resourcePolicy",
    echoedByGateway: false,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function finiteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) {
    return Number(value);
  }
  return undefined;
}

/**
 * Overlay a live PUT `/json/controls/policyLayers` echo onto the SDK annotation.
 * The live body is flat: `{ customCategoryId, customType: <numeric>, enum, listKind, message }`.
 * Missing any of numeric `customType`, `enum`, or `listKind` leaves the annotation unchanged.
 */
export function applyGatewayCreateEcho(
  annotation: ResourcePolicyWireKindAnnotation,
  createResponse: unknown,
): ResourcePolicyWireKindAnnotation {
  if (!isPlainObject(createResponse)) return annotation;
  const enumName = typeof createResponse.enum === "string" ? createResponse.enum.trim() : "";
  const listKind = createResponse.listKind;
  const numeric = finiteNumber(createResponse.customType);
  if (!enumName || numeric === undefined) return annotation;
  if (listKind !== "resourcePolicy" && listKind !== "policyLayer") return annotation;
  const fromEnum = wireKindFromCustomType(enumName);
  return {
    kind: fromEnum?.kind ?? annotation.kind,
    customType: enumName,
    numeric,
    listKind,
    echoedByGateway: true,
  };
}

export function isResourcePolicyKind(value: string): value is ResourcePolicyKind {
  return (RESOURCE_POLICY_KINDS as readonly string[]).includes(value);
}

/**
 * `kind` wins as the structure selector. `type` remains the legacy alias for
 * blocklist / allowlist / categories. Passing both is allowed only when they
 * name the same kind.
 */
export function resolveResourcePolicyKind(params: {
  type?: "blocklist" | "allowlist" | "categories";
  kind?: ResourcePolicyKind;
}): ResourcePolicyKindWire {
  if (params.kind !== undefined && !isResourcePolicyKind(params.kind)) {
    throw new TypeError(
      `Unknown resource policy kind "${String(params.kind)}". Expected one of: ${RESOURCE_POLICY_KINDS.join(", ")}.`,
    );
  }
  if (params.kind && params.type) {
    const fromKind = RESOURCE_POLICY_KIND_WIRE[params.kind];
    if (fromKind.layerType !== params.type) {
      throw new TypeError(
        `createResourcePolicy kind "${params.kind}" does not match type "${params.type}". Pass kind or type, not both.`,
      );
    }
  }
  if (params.kind) return RESOURCE_POLICY_KIND_WIRE[params.kind];
  if (params.type) return RESOURCE_POLICY_KIND_WIRE[params.type];
  return RESOURCE_POLICY_KIND_WIRE.categories;
}

export function wireKindFromCustomType(customType: string): ResourcePolicyKindWire | undefined {
  return Object.values(RESOURCE_POLICY_KIND_WIRE).find((wire) => wire.customType === customType);
}

/**
 * True when GET `customType` / `categoryType` is the enum we sent, the numeric
 * alias, or (categories only) the alternate GET value 13.
 * Missing values match — some reads omit the field (DEVELOP-34958).
 */
export function customTypeMatchesKind(actual: unknown, wire: ResourcePolicyKindWire): boolean {
  if (actual === undefined || actual === null || actual === "") return true;
  if (actual === wire.customType) return true;
  if (actual === wire.numeric || actual === String(wire.numeric)) return true;
  if (wire.kind === "categories" && (actual === 13 || actual === "13")) return true;
  return false;
}

function rejectedNumericCustomType(value: number | string, where: string): IbossPolicyTypeError {
  const kind: ResourcePolicyKind = value === 6 || value === "6" ? "urlList" : "parent";
  const wire = RESOURCE_POLICY_KIND_WIRE[kind];
  return new IbossPolicyTypeError(
    `${where} is numeric customType ${value}. ` +
      `Use createResourcePolicy({ kind: "${kind}", ... }) which sends "${wire.customType}" and does not send ${value}. ` +
      `Live Gateway accepts numeric 6 and 10 (DEVELOP-34958); the SDK still refuses them so older nodes are not sent a value they reject.`,
    { customType: value },
  );
}

/**
 * Fail before PUT/POST when a caller would send numeric 6 or 10.
 * Enum strings pass through. Other numerics are left to the gateway.
 */
export function assertGatewayAcceptsCustomType(value: unknown, where: string): void {
  if (typeof value === "number" && (value === 6 || value === 10)) {
    throw rejectedNumericCustomType(value, where);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed === "6" || trimmed === "10") {
      throw rejectedNumericCustomType(trimmed, where);
    }
  }
}
