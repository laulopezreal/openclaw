import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import { Readable, Writable } from "node:stream";
import { PROTOCOL_VERSION, agent, methods, ndJsonStream } from "@agentclientprotocol/sdk";

const resultPath = process.env.ACPX_SCHTASKS_PROOF_RESULT_PATH;
if (!resultPath) {
  throw new Error("ACPX_SCHTASKS_PROOF_RESULT_PATH is required");
}

const proofAgent = agent({ name: "openclaw-schtasks-permission-proof" })
  .onRequest(methods.agent.initialize, () => ({
    protocolVersion: PROTOCOL_VERSION,
    agentCapabilities: { loadSession: false },
  }))
  .onRequest(methods.agent.session.new, () => ({ sessionId: randomUUID() }))
  .onRequest(methods.agent.session.prompt, async ({ params, client }) => {
    const startedAt = Date.now();
    const permission = await client.request(methods.client.session.requestPermission, {
      sessionId: params.sessionId,
      toolCall: {
        toolCallId: "scheduled-task-permission",
        kind: "execute",
        title: "Scheduled Task permission proof",
      },
      options: [
        { kind: "allow_once", name: "Allow once", optionId: "allow" },
        { kind: "reject_once", name: "Reject once", optionId: "deny" },
      ],
    });
    await fs.writeFile(
      resultPath,
      `${JSON.stringify({
        elapsedMs: Date.now() - startedAt,
        outcome: permission.outcome.outcome,
        optionId: permission.outcome.outcome === "selected" ? permission.outcome.optionId : null,
      })}\n`,
      "utf8",
    );
    return { stopReason: "end_turn" };
  })
  .onNotification(methods.agent.session.cancel, () => {});

proofAgent.connect(ndJsonStream(Writable.toWeb(process.stdout), Readable.toWeb(process.stdin)));
