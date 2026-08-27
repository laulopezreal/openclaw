import { describe, expect, it } from "vitest";
import { assertAcpPermissionProof } from "../../scripts/windows-schtasks-acp-permission-proof.mts";

describe("windows schtasks ACP permission proof", () => {
  it("accepts only the prompt non-interactive deny result", () => {
    expect(() =>
      assertAcpPermissionProof({ elapsedMs: 5_000, optionId: "deny", outcome: "selected" }),
    ).not.toThrow();
    expect(() =>
      assertAcpPermissionProof({ elapsedMs: 5_001, optionId: "deny", outcome: "selected" }),
    ).toThrow("ACP permission request did not take the prompt non-interactive deny path");
    expect(() =>
      assertAcpPermissionProof({ elapsedMs: 1, optionId: null, outcome: "cancelled" }),
    ).toThrow("ACP permission request did not take the prompt non-interactive deny path");
  });
});
