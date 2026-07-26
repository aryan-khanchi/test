'use strict';
const db = require('./db');
const { canonicalStringify, digestOf, sha256Hex } = require('./canonical');
const { validateProposeRequest } = require('./schema');
const { decideBatch } = require('./model');
const { buildAndValidateProposal, fallbackProposal } = require('./actions');
const { errorBody, PROFILE } = require('./util');

function dossierFingerprint(dossier) {
  return sha256Hex(canonicalStringify(dossier));
}

// Deterministic callId derived from dossierId + content fingerprint. This
// guarantees the "stable unique tool-call id" requirement across repeated
// evaluations without needing a prior DB row to exist yet, and it stays
// stable even if the process restarts between Checks.
function callIdFor(dossierId, fingerprint) {
  const h = sha256Hex(dossierId + ':' + fingerprint).slice(0, 40);
  return `call-${h}`;
}

async function handlePropose(body) {
  const check = validateProposeRequest(body);
  if (!check.ok) {
    return { httpStatus: check.status, body: errorBody(body, check.message) };
  }

  const { evaluationId, dossiers, allowedActions, receiptVerifier } = body;
  const dossiersDigest = digestOf(dossiers);

  const existingEval = db.prepare('SELECT * FROM evaluations WHERE evaluation_id = ?').get(evaluationId);
  if (existingEval) {
    if (existingEval.input_digest === dossiersDigest) {
      // Exact replay: return the stored response verbatim, no model work.
      return { httpStatus: 200, body: JSON.parse(existingEval.response_json) };
    }
    return {
      httpStatus: 409,
      body: errorBody(body, 'evaluationId already used with different dossier content'),
    };
  }

  // --- Look up per-dossier cache by canonical content fingerprint ---
  const proposals = [];
  const uncached = [];
  const fingerprintByDossierId = {};

  const lookupStmt = db.prepare('SELECT * FROM dossier_decisions WHERE fingerprint = ?');
  for (const d of dossiers) {
    const fp = dossierFingerprint(d);
    fingerprintByDossierId[d.dossierId] = fp;
    const row = lookupStmt.get(fp);
    if (row) {
      proposals.push({
        dossierId: d.dossierId,
        callId: row.call_id,
        action: row.action,
        target: row.target_json ? JSON.parse(row.target_json) : null,
        payload: JSON.parse(row.payload_json),
        evidence: JSON.parse(row.evidence_json),
      });
    } else {
      uncached.push(d);
    }
  }

  if (uncached.length > 0) {
    const decisions = await decideBatch(uncached, allowedActions);

    const insertStmt = db.prepare(`
      INSERT INTO dossier_decisions
        (fingerprint, dossier_id, call_id, action, target_json, payload_json, evidence_json, created_at)
      VALUES (@fingerprint, @dossier_id, @call_id, @action, @target_json, @payload_json, @evidence_json, @created_at)
      ON CONFLICT(fingerprint) DO NOTHING
    `);
    const insertMany = db.transaction((rows) => {
      for (const r of rows) insertStmt.run(r);
    });

    const rowsToInsert = [];
    for (const d of uncached) {
      const fp = fingerprintByDossierId[d.dossierId];
      const callId = callIdFor(d.dossierId, fp);
      const raw = decisions.get(d.dossierId);

      let finalProposal;
      try {
        finalProposal = buildAndValidateProposal(raw, d, allowedActions, callId);
      } catch (err) {
        console.error(`[propose] falling back for dossier ${d.dossierId}: ${err.message}`);
        finalProposal = fallbackProposal(d, callId);
      }

      proposals.push({ dossierId: d.dossierId, ...finalProposal });
      rowsToInsert.push({
        fingerprint: fp,
        dossier_id: d.dossierId,
        call_id: finalProposal.callId,
        action: finalProposal.action,
        target_json: finalProposal.target ? JSON.stringify(finalProposal.target) : null,
        payload_json: JSON.stringify(finalProposal.payload),
        evidence_json: JSON.stringify(finalProposal.evidence),
        created_at: new Date().toISOString(),
      });
    }
    insertMany(rowsToInsert);
  }

  // Preserve the order of the incoming dossiers array in the response.
  const orderIndex = new Map(dossiers.map((d, i) => [d.dossierId, i]));
  proposals.sort((a, b) => orderIndex.get(a.dossierId) - orderIndex.get(b.dossierId));

  const responseBody = {
    profile: PROFILE,
    evaluationId,
    status: 'awaiting_receipts',
    inputDigest: dossiersDigest,
    proposals,
  };

  try {
    db.prepare(`
      INSERT INTO evaluations
        (evaluation_id, input_digest, receipt_verifier_json, proposals_json, response_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      evaluationId,
      dossiersDigest,
      JSON.stringify(receiptVerifier),
      JSON.stringify(proposals),
      JSON.stringify(responseBody),
      new Date().toISOString()
    );
  } catch (err) {
    // Lost a race with a concurrent identical request for this evaluationId.
    const row = db.prepare('SELECT * FROM evaluations WHERE evaluation_id = ?').get(evaluationId);
    if (row && row.input_digest === dossiersDigest) {
      return { httpStatus: 200, body: JSON.parse(row.response_json) };
    }
    throw err;
  }

  return { httpStatus: 200, body: responseBody };
}

module.exports = { handlePropose, dossierFingerprint, callIdFor };
