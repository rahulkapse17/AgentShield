/**
 * AgentShield (PS-01) - Tamper-Evident Audit Trail Module
 * Maintains an append-only event ledger secured with SHA-256 cryptographic hash chaining.
 */

import crypto from 'node:crypto';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

class AuditLogger {
  constructor() {
    this.logs = [];
    this.latestHash = GENESIS_HASH;
  }

  /**
   * Sanitizes arguments to prevent logging sensitive secrets or credentials in plain text.
   */
  sanitizeArgs(toolName, args = {}) {
    const copy = { ...args };
    if (copy.password) copy.password = '[REDACTED]';
    if (copy.token) copy.token = '[REDACTED]';
    if (copy.apiKey) copy.apiKey = '[REDACTED]';
    return copy;
  }

  /**
   * Records a security decision into the tamper-evident chain.
   */
  logDecision(evalResult) {
    const id = this.logs.length + 1;
    const timestamp = evalResult.timestamp || new Date().toISOString();
    const sanitizedArgs = this.sanitizeArgs(evalResult.toolName, evalResult.args);

    const recordPayload = {
      id,
      timestamp,
      toolName: evalResult.toolName || 'unknown',
      argsSummary: sanitizedArgs,
      provenance: evalResult.provenance || 'unknown',
      decision: evalResult.decision,
      status: evalResult.status || evalResult.decision,
      riskLevel: evalResult.riskLevel || 'LOW',
      ruleId: evalResult.ruleId || 'N/A',
      reason: evalResult.reason || '',
      prevHash: this.latestHash
    };

    // Calculate cryptographic SHA-256 hash linking to previous record
    const hashData = JSON.stringify(recordPayload);
    const recordHash = crypto.createHash('sha256').update(hashData).digest('hex');

    const logEntry = {
      ...recordPayload,
      recordHash
    };

    this.logs.push(logEntry);
    this.latestHash = recordHash;

    return logEntry;
  }

  getAuditLogs() {
    return [...this.logs];
  }

  getAuditStats() {
    const stats = {
      total: this.logs.length,
      allow: 0,
      deny: 0,
      approval: 0,
      injectBlocked: 0,
      unshielded: 0
    };

    for (const entry of this.logs) {
      if (entry.status === 'ALLOWED') stats.allow++;
      else if (entry.status === 'DENIED') stats.deny++;
      else if (entry.status === 'REQUIRES_APPROVAL') stats.approval++;
      else if (entry.status === 'INJECT_BLOCKED') stats.injectBlocked++;
      else if (entry.status === 'UNSHIELDED') stats.unshielded++;
    }

    return stats;
  }

  /**
   * Cryptographically verifies the integrity of the entire audit chain.
   * If any entry was tampered with, modified, or deleted, this returns isValid: false.
   */
  verifyAuditIntegrity() {
    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < this.logs.length; i++) {
      const entry = this.logs[i];

      // 1. Check prevHash pointer
      if (entry.prevHash !== expectedPrevHash) {
        return {
          isValid: false,
          brokenIndex: i,
          error: `Broken chain link at log entry #${entry.id}. Expected prevHash: ${expectedPrevHash}, found: ${entry.prevHash}`
        };
      }

      // 2. Recompute hash
      const payloadToCheck = {
        id: entry.id,
        timestamp: entry.timestamp,
        toolName: entry.toolName,
        argsSummary: entry.argsSummary,
        provenance: entry.provenance,
        decision: entry.decision,
        status: entry.status,
        riskLevel: entry.riskLevel,
        ruleId: entry.ruleId,
        reason: entry.reason,
        prevHash: entry.prevHash
      };

      const recomputedHash = crypto.createHash('sha256').update(JSON.stringify(payloadToCheck)).digest('hex');

      if (recomputedHash !== entry.recordHash) {
        return {
          isValid: false,
          brokenIndex: i,
          error: `Tampering detected at log entry #${entry.id}. Recomputed hash does not match stored recordHash.`
        };
      }

      expectedPrevHash = entry.recordHash;
    }

    return {
      isValid: true,
      verifiedRecords: this.logs.length,
      headHash: this.latestHash
    };
  }

  clear() {
    this.logs = [];
    this.latestHash = GENESIS_HASH;
  }
}

export const auditLogger = new AuditLogger();

