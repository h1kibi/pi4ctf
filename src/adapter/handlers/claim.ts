import { ClaimVerifier } from '../../kernel/claim/verifier.js';
import { Ledger } from '../../kernel/ledger/store.js';
import type { Request, Response } from '../types.js';
import { needRoot, ok, str } from '../helpers.js';

export async function handleClaim(req: Request, op: string, input: Record<string, unknown>): Promise<Response> {
  if (op !== 'claim') throw new Error(`unexpected claim op: ${op}`);
  const project = needRoot(req);
  const verifier = new ClaimVerifier(project, new Ledger(project));
  const claim = verifier.submit({
    claimType: str(input, 'claimType'),
    text: str(input, 'text'),
    quotes: Array.isArray(input.quotes) ? (input.quotes as ClaimQuoteInput[]) : [],
    refs: Array.isArray(input.refs) ? (input.refs as unknown[]).map(String) : [],
    probe: input.probe as { purpose: string; expect: string; falsifier: string } | undefined,
    predicate: input.predicate ? String(input.predicate) : undefined,
  });
  const verified = verifier.verify(claim.id);
  return ok(op, { claim: verified });
}

interface ClaimQuoteInput {
  shapedRef: string;
  span?: { start: number; end: number };
  text: string;
}
