import { CLAUDE_CLI_PROFILE_ID } from "openclaw/plugin-sdk/provider-auth";
import { describe, expect, it } from "vitest";
import { CLAUDE_CLI_RETIRED_PROFILE_ID } from "./cli-constants.js";

describe("claude cli constants", () => {
  it("keeps the retired profile id aligned with the plugin-sdk constant", () => {
    // The policy-surface artifact must stay light, so the plugin carries this
    // id as a local literal instead of importing the provider-auth barrel.
    expect(CLAUDE_CLI_RETIRED_PROFILE_ID).toBe(CLAUDE_CLI_PROFILE_ID);
  });
});
