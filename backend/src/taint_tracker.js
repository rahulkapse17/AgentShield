/**
 * AgentShield (PS-01) - Taint Tracking & Data Provenance Engine
 * Enforces the core paradigm: "DATA IS NOT AUTHORITY"
 * Tracks source origin and detects indirect prompt injections inside untrusted content.
 */

import { hybridSearchScan } from './hybrid_search.js';

export const PROVENANCE_LEVELS = {
  TRUSTED_USER: 'TRUSTED_USER',
  SYSTEM_POLICY: 'SYSTEM_POLICY',
  UNTRUSTED_CONTENT: 'UNTRUSTED_CONTENT'
};

export class SessionProvenanceTracker {
  constructor(sessionId, userPrompt) {
    this.sessionId = sessionId || `sess_${Date.now()}`;
    this.userPrompt = userPrompt || '';
    this.history = [];
    this.taintedSources = [];
    this.isContextTainted = false;
    this.detectedInjection = null;
    this.hybridScan = null;

    // Record root user intent
    this.recordEvent({
      type: 'USER_PROMPT',
      source: PROVENANCE_LEVELS.TRUSTED_USER,
      contentSummary: this.userPrompt,
      timestamp: new Date().toISOString()
    });
  }

  recordEvent(event) {
    this.history.push({
      ...event,
      timestamp: event.timestamp || new Date().toISOString()
    });
  }

  /**
   * Called whenever the agent ingests external data (e.g. after reading a file).
   * Runs Hybrid Search (Deterministic Regex + Semantic Vector Space) to detect
   * direct and paraphrased prompt injections.
   */
  ingestContent(sourceIdentifier, content) {
    const isUntrusted = !sourceIdentifier.startsWith('system/') && !sourceIdentifier.startsWith('policy/');
    
    // Execute Hybrid Search scan (Layer 1 Regex + Layer 2 Semantic Embeddings)
    const scan = hybridSearchScan(content);
    this.hybridScan = scan;

    if (isUntrusted) {
      this.isContextTainted = true;
      this.taintedSources.push(sourceIdentifier);
    }

    if (scan.isMalicious) {
      this.detectedInjection = {
        source: sourceIdentifier,
        method: scan.primaryDetectionMethod,
        threatScore: scan.threatScore,
        topIntent: scan.topIntent,
        layer1: scan.layer1Deterministic,
        layer2: scan.layer2Semantic,
        snippet: content.substring(0, 200) + '...'
      };
    }

    this.recordEvent({
      type: 'CONTENT_INGESTED',
      source: isUntrusted ? PROVENANCE_LEVELS.UNTRUSTED_CONTENT : PROVENANCE_LEVELS.SYSTEM_POLICY,
      identifier: sourceIdentifier,
      tainted: isUntrusted,
      injectionDetected: scan.isMalicious,
      hybridScan: scan
    });

    return {
      isTainted: isUntrusted,
      injectionDetected: scan.isMalicious,
      hybridScan: scan,
      details: this.detectedInjection
    };
  }

  /**
   * Helper to verify if the user explicitly asked for a specific target.
   * Fail closed: treats empty, missing, or very short targets (< 3 chars) as NOT asked.
   */
  userExplicitlyAsked(target) {
    if (!this.userPrompt || typeof this.userPrompt !== 'string') return false;
    const cleanTarget = String(target || '').trim();
    if (!cleanTarget || cleanTarget.length < 3) {
      return false;
    }
    return this.userPrompt.toLowerCase().includes(cleanTarget.toLowerCase());
  }

  /**
   * Evaluates whether a proposed tool call is influenced by tainted content
   * or diverges from the user's initial intent.
   */
  inspectToolProvenance(toolName, args = {}) {
    // If an indirect injection was already detected in any ingested file,
    // any sensitive or external action is immediately flagged as INJECT_BLOCKED.
    if (this.detectedInjection) {
      const targetResource = String(args.path || args.filePath || args.to || args.query || '').trim();
      
      // Check if user prompt actually requested this target (fail closed on empty/short)
      const userAskedForThis = this.userExplicitlyAsked(targetResource);

      if (!userAskedForThis) {
        return {
          isBlockedByInjection: true,
          provenance: `tainted:${this.detectedInjection.source}`,
          reason: `Indirect prompt injection detected in '${this.detectedInjection.source}'. Ingested data attempted to coerce tool '${toolName}' on '${targetResource || 'unspecified'}' without user authority.`
        };
      }
    }

    return {
      isBlockedByInjection: false,
      provenance: this.isContextTainted ? `tainted:${this.taintedSources.join(',')}` : PROVENANCE_LEVELS.TRUSTED_USER,
      reason: null
    };
  }

  getTrace() {
    return {
      sessionId: this.sessionId,
      userPrompt: this.userPrompt,
      isContextTainted: this.isContextTainted,
      taintedSources: this.taintedSources,
      detectedInjection: this.detectedInjection,
      events: this.history
    };
  }
}

