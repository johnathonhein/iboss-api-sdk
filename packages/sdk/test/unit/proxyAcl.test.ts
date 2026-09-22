import { describe, expect, it } from "vitest";
import {
  moveProxyAclRules,
  normalizeProxyAclRules,
  proxyAclOrderKeys,
  resolveProxyAclDestination,
} from "../../src/api/proxyAcl.js";

const rules = normalizeProxyAclRules([
  { index: 0, name: "A" },
  { index: 1, name: "B" },
  { index: 2, name: "C" },
  { index: 3, name: "D" },
]);

describe("proxy ACL order (DEVELOP-34959)", () => {
  it("moves id into the slot of toId", () => {
    const moved = moveProxyAclRules(rules, 1, 3);
    expect(proxyAclOrderKeys(moved)).toEqual(["name:A", "name:C", "name:D", "name:B"]);
  });

  it("resolves beforeRuleId and afterRuleId to a toId", () => {
    expect(resolveProxyAclDestination(rules, { id: 0, beforeRuleId: 2 })).toEqual({
      fromIndex: 0,
      toIndex: 1,
    });
    expect(proxyAclOrderKeys(moveProxyAclRules(rules, 0, 1))).toEqual([
      "name:B",
      "name:A",
      "name:C",
      "name:D",
    ]);
    expect(resolveProxyAclDestination(rules, { id: 3, afterRuleId: 1 })).toEqual({
      fromIndex: 3,
      toIndex: 2,
    });
    expect(proxyAclOrderKeys(moveProxyAclRules(rules, 3, 2))).toEqual([
      "name:A",
      "name:B",
      "name:D",
      "name:C",
    ]);
  });

  it("treats an already-adjacent alias as a no-op toId", () => {
    expect(resolveProxyAclDestination(rules, { id: 0, beforeRuleId: 1 }).toIndex).toBe(0);
  });

  it("requires exactly one destination selector", () => {
    expect(() => resolveProxyAclDestination(rules, { id: 0, toId: 1, beforeRuleId: 2 })).toThrow(
      /exactly one/,
    );
    expect(() => resolveProxyAclDestination(rules, { id: 9, toId: 1 })).toThrow(/absolute index 9/);
  });
});
