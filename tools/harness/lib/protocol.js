'use strict';

/**
 * Real (not hardcoded-verdict) implementation of the Track 1 routing-validation logic
 * documented and verified in docs/threat-model.md sections 6/9 and
 * docs/state-invariants.md row 3. Given raw header/body inputs, it computes the verdict --
 * it does not accept the verdict as an input. This is what lets us claim the fixtures are
 * "protocol-conformant harness-generated," not "hand-labeled."
 *
 * `headerRequired(protocolVersion)` mirrors the MCP 2026-07-28 changelog: Mcp-Method/Mcp-Name
 * were introduced by SEP-2243 in the 2026-07-28 revision. Earlier negotiated versions never
 * defined these headers, so their absence there is compatibility, not a violation.
 */
function headerRequired(protocolVersion) {
  return protocolVersion === '2026-07-28';
}

/**
 * header: { present: boolean, malformed?: boolean, value?: string|null }
 * bodyValue: string
 */
function validateField(protocolVersion, header, bodyValue) {
  if (!headerRequired(protocolVersion)) return 'version_incompatible';
  if (!header.present) return 'missing';
  if (header.malformed) return 'malformed';
  if (header.value === bodyValue) return 'match';
  return 'conflict';
}

const NAME_APPLICABLE_METHODS = new Set([
  'tools/call', 'resources/read', 'prompts/get',
  'tasks/get', 'tasks/update', 'tasks/cancel'
]);

function validateName(protocolVersion, header, bodyIdentity, method) {
  if (!headerRequired(protocolVersion)) return 'version_incompatible';
  if (!NAME_APPLICABLE_METHODS.has(method)) return 'not_applicable';
  if (!header.present) return 'missing';
  if (header.malformed) return 'malformed';
  if (header.value === bodyIdentity) return 'match';
  return 'conflict';
}

const BAD_RESULTS = new Set(['conflict', 'missing', 'malformed']);

function rollup(methodResult, nameResult) {
  return (BAD_RESULTS.has(methodResult) || BAD_RESULTS.has(nameResult)) ? 'invalid' : 'valid';
}

function taskOperationFor(method) {
  const map = { 'tasks/get': 'get', 'tasks/update': 'update', 'tasks/cancel': 'cancel' };
  if (!(method in map)) throw new Error(`no task operation mapping for method ${method}`);
  return map[method];
}

module.exports = { headerRequired, validateField, validateName, rollup, taskOperationFor, NAME_APPLICABLE_METHODS };
