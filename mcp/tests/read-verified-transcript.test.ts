// SPDX-License-Identifier: Apache-2.0
//
// tclk_read_verified_transcript: the authenticated combination of tclk_read_room and
// foldTranscript. The regression this file exists to pin down is #158's exact attack:
// a frame whose own `from` field claims one of the two real parties, actually signed
// by an unrelated third identity, must never advance settlement state.
//
// tclk_read_verified_transcript reads one room per call, matching tclk_read_room's own
// contract exactly. Offer and accept both authenticate within OFFER_ROOM alone, so the
// forgery tests below stay within a single room read -- a fully realistic, self-
// contained reproduction of the vulnerability class, not an artifact of test setup.

import { describe, expect, it } from "vitest";

import { OFFER_ROOM } from "@flop-labs/tclk";
import { canonicalMessage, signerFromSeed } from "../src/signing.js";
import { createHandlers } from "../src/tools.js";
import {
  ATTACKER_SEED,
  HASH_OFFER,
  NOW,
  PAYEE_DID,
  PAYEE_SEED,
  PAYER_DID,
  PAYER_SEED,
  fakeFetch,
  hexToBytes,
} from "./fixtures.js";

const payer = signerFromSeed(hexToBytes(PAYER_SEED));
const payee = signerFromSeed(hexToBytes(PAYEE_SEED));
const attacker = signerFromSeed(hexToBytes(ATTACKER_SEED));

function envelope(seq: number, signer: typeof payer, room: string, nonce: number, line: string) {
  return {
    seq,
    ts: new Date(NOW + seq).toISOString(),
    from: signer.did,
    nonce: String(nonce),
    sig: signer.sign(canonicalMessage(room, nonce, line)),
    text: line,
  };
}

describe("tclk_read_verified_transcript", () => {
  it("folds a genuine offer -> accept the same way tclk_apply_transcript would", async () => {
    const h = createHandlers({ env: {} });
    const offer = h.tclk_make_offer(HASH_OFFER);
    const accept = h.tclk_accept_offer({ offer: offer.line, from: PAYEE_DID });

    const { fetchLike } = fakeFetch([
      {
        body: "",
        json: {
          room: OFFER_ROOM,
          count: 2,
          last_seq: 1,
          messages: [
            envelope(0, payer, OFFER_ROOM, 100, offer.line),
            envelope(1, payee, OFFER_ROOM, 101, accept.line),
          ],
        },
      },
    ]);
    const handlers = createHandlers({ env: {}, fetch: fetchLike });

    const result = await handlers.tclk_read_verified_transcript({ room: OFFER_ROOM });

    expect(result.room).toBe(OFFER_ROOM);
    expect(result.source).toBe("window");
    expect(result.steps.map((s) => s.ok)).toEqual([true, true]);
    expect(result.state).not.toBeNull();
    expect(result.state!.status).toBe("accepted");
    expect(result.state!.contract).toBe(accept.contract);
    expect(result.state!.parties).toEqual({
      payer: PAYER_DID,
      payee: PAYEE_DID,
      payerKey: null,
      payeeKey: null,
    });
    expect(result.rejectedCount).toBe(0);
  });

  it("#158 regression: a frame forging another party's `from` never advances state", async () => {
    const h = createHandlers({ env: {} });
    const offer = h.tclk_make_offer(HASH_OFFER);
    // The forged frame: format-valid, `from` claims the real payee, everything else
    // about the accept is a real, well-formed acceptance of this real offer -- but it
    // is signed and posted by an unrelated attacker identity, exactly the shape
    // reported in #158 (a frame claiming a real party's identity from a third DID).
    const forgedAccept = h.tclk_accept_offer({ offer: offer.line, from: PAYEE_DID });

    const { fetchLike } = fakeFetch([
      {
        body: "",
        json: {
          room: OFFER_ROOM,
          count: 2,
          last_seq: 1,
          messages: [
            envelope(0, payer, OFFER_ROOM, 200, offer.line),
            // Real technocore sender is the attacker; the frame text's own `from`
            // field still says payee. This is the exact mismatch foldTranscript
            // exists to catch -- and this tool must never silently trust it.
            envelope(1, attacker, OFFER_ROOM, 201, forgedAccept.line),
          ],
        },
      },
    ]);
    const handlers = createHandlers({ env: {}, fetch: fetchLike });

    const result = await handlers.tclk_read_verified_transcript({ room: OFFER_ROOM });

    expect(result.state).not.toBeNull();
    // The genuine offer opens the contract; the forged accept is rejected, so the
    // contract never leaves "proposed" -- an auditor reading this room sees an open
    // offer, not a completed, payee-accepted deal.
    expect(result.state!.status).toBe("proposed");

    expect(result.steps).toHaveLength(2);
    expect(result.steps[0]).toMatchObject({ ok: true, type: "offer" });
    expect(result.steps[1]).toMatchObject({
      ok: false,
      type: "accept",
      reason: "accept.from does not match the record sender",
    });
    expect(result.rejectedCount).toBe(1);
    expect(attacker.did).not.toBe(PAYEE_DID);
  });

  it("reports state: null, not a throw, when nothing has authenticated yet", async () => {
    const room = "mb-p-tclk-quiet";
    const { fetchLike } = fakeFetch([
      {
        body: "",
        json: {
          room,
          count: 1,
          last_seq: 0,
          messages: [{ seq: 0, ts: "2026-01-01T00:00:00Z", from: "~someone", text: "gm" }],
        },
      },
    ]);
    const h = createHandlers({ env: {}, fetch: fetchLike });

    const result = await h.tclk_read_verified_transcript({ room });
    expect(result.state).toBeNull();
    expect(result.rejectedCount).toBe(1);
  });
});
