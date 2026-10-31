/**
 * AgentShield (PS-01) - Policy Enforcement Point (PEP) Decision Pipeline
 * Unifies Static Policy, Taint Provenance, and Strict Fail-Closed Guards.
 */

import { evaluateStaticPolicy, isRiskyToolCall, DECISIONS, RISK_LEVELS } from './policy_rules.js';

export class PolicyEngine {
  /**
   * Main Policy Evaluation Point (PEP)
   * Evaluates any proposed tool invocation against provenance, static policy, and fail-closed rules.
   *
   * @param {string} toolName - Name of the tool requested by the agent
   * @param {object} args - Tool arguments (paths, queries, recipients, etc.)
   * @param {SessionProvenanceTracker} [provenanceTracker] - Active session provenance tracker
   * @param {object} [userContext] - Metadata about the calling user
   */
  static evaluateToolCall(toolName, args = {}, provenanceTracker = null, userContext = {}) {
    const timestamp = new Date().toISOString();

    try {
      // 1. FAIL-CLOSED CHECK: Validate Tool Name
      if (!toolName || typeof toolName !== 'string') {
        return {
          decision: DECISIONS.DENY,
          status: 'DENIED',
          toolName: toolName || 'unknown',
          args,
          provenance: 'unknown',
          riskLevel: RISK_LEVELS.CRITICAL,
          ruleId: 'FAIL_CLOSED_INVALID_TOOL_NAME',
          reason: 'Tool name missing or invalid. Fail-closed rejection.',
          timestamp
        };
      }

      // 2. FAIL-CLOSED CHECK: Validate User Authorization Context
      if (userContext && userContext.clearance === 'REVOKED') {
        return {
          decision: DECISIONS.DENY,
          status: 'DENIED',
          toolName,
          args,
          provenance: 'user:revoked',
          riskLevel: RISK_LEVELS.CRITICAL,
          ruleId: 'FAIL_CLOSED_USER_REVOKED',
          reason: 'User session credentials revoked or clearance unverified.',
          timestamp
        };
      }

      // 3. PROVENANCE & INDIRECT PROMPT INJECTION CHECK
      let provenanceSource = 'TRUSTED_USER';
      if (provenanceTracker) {
        const provCheck = provenanceTracker.inspectToolProvenance(toolName, args);
        provenanceSource = provCheck.provenance;

        if (provCheck.isBlockedByInjection) {
          return {
            decision: DECISIONS.DENY,
            status: 'INJECT_BLOCKED',
            toolName,
            args,
            provenance: provCheck.provenance,
            riskLevel: RISK_LEVELS.CRITICAL,
            ruleId: 'RULE_INDIRECT_INJECTION_DETECTED',
            reason: provCheck.reason,
            timestamp
          };
        }
      }

      // 3.1 TAINTED SESSION BACKSTOP CHECK: Missed-detection containment
      // If untrusted content was ingested, the tool is risky, and the user did not explicitly request it,
      // fail closed with INJECT_BLOCKED even when the detector did not flag the ingested content.
      if (provenanceTracker && provenanceTracker.isContextTainted) {
        if (isRiskyToolCall(toolName, args)) {
          const rawTarget = args.path || args.filePath || args.to || args.query || '';
          const userAsked = provenanceTracker.userExplicitlyAsked(rawTarget);

          if (!userAsked) {
            return {
              decision: DECISIONS.DENY,
              status: 'INJECT_BLOCKED',
              toolName,
              args,
              provenance: provenanceSource,
              riskLevel: RISK_LEVELS.CRITICAL,
              ruleId: 'RULE_TAINTED_RISKY_TOOL',
              reason: 'Session contains untrusted content and this action was not requested by the user.',
              timestamp
            };
          }
        }
      }

      // 4. STATIC POLICY MATRIX EVALUATION
      const staticResult = evaluateStaticPolicy(toolName, args);

      // Map decision to display status
      let displayStatus = 'DENIED';
      if (staticResult.decision === DECISIONS.ALLOW) {
        displayStatus = 'ALLOWED';
      } else if (staticResult.decision === DECISIONS.REQUIRE_APPROVAL) {
        displayStatus = 'REQUIRES_APPROVAL';
      }

      return {
        decision: staticResult.decision,
        status: displayStatus,
        toolName,
        args,
        provenance: provenanceSource,
        riskLevel: staticResult.riskLevel,
        ruleId: staticResult.ruleId,
        reason: staticResult.reason,
        timestamp
      };

    } catch (evalError) {
      // 5. FAIL-CLOSED FALLBACK: If policy evaluation throws ANY exception, fail closed immediately
      return {
        decision: DECISIONS.DENY,
        status: 'DENIED',
        toolName,
        args,
        provenance: 'error_fallback',
        riskLevel: RISK_LEVELS.CRITICAL,
        ruleId: 'FAIL_CLOSED_SYSTEM_EXCEPTION',
        reason: `Policy engine encountered an unexpected internal error: ${evalError.message}. Executing fail-closed block.`,
        timestamp
      };
    }
  }
}

