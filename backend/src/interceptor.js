/**
 * AgentShield (PS-01) - Security Interception Proxy
 * Intercepts tool calls between the AI Agent and the underlying environment.
 * Ensures NO tool call executes without prior policy verification and audit logging.
 */

import { PolicyEngine } from './policy_engine.js';
import { auditLogger } from './audit_logger.js';
import { mockReadFile, mockSendEmail, mockQueryDatabase, mockDeleteFile } from './mock_tools.js';
import { shieldState } from './shield_state.js';

// In-memory registry for actions requiring human supervisor sign-off
export const pendingApprovals = new Map();

/**
 * Dispatches an approved tool call to the corresponding mock tool handler.
 */
async function dispatchToolExecution(toolName, args, sessionTracker = null) {
  let output;
  switch (toolName) {
    case 'read_file':
      output = await mockReadFile(args.path || args.filePath);
      // Ingest content into session tracker for dynamic taint tracking
      if (sessionTracker) {
        sessionTracker.ingestContent(args.path || args.filePath, output);
      }
      return output;

    case 'send_email':
      return await mockSendEmail(args);

    case 'query_database':
      return await mockQueryDatabase(args);

    case 'delete_file':
      return await mockDeleteFile(args);

    default:
      throw new Error(`EXECUTION_DISPATCH_FAILED: Tool '${toolName}' handler not found.`);
  }
}

/**
 * Core Interception Gateway
 * Intercepts, inspects, audits, and constrains tool invocations.
 */
export async function interceptToolCall({
  toolName,
  args = {},
  sessionTracker = null,
  userContext = {},
  bypassSecurity = false // For testing what happens WITHOUT AgentShield
}) {
  // SHIELD OFF HANDLING: If Shield is globally OFF or bypass requested
  if (!shieldState.enabled || bypassSecurity) {
    // Record execution in tamper-evident audit trail with UNSHIELDED status
    const offEvaluation = {
      timestamp: new Date().toISOString(),
      toolName,
      args,
      provenance: sessionTracker ? `unshielded:${sessionTracker.sessionId}` : 'unshielded',
      decision: 'ALLOW',
      status: 'UNSHIELDED',
      riskLevel: 'CRITICAL',
      ruleId: 'SHIELD_OFF',
      reason: 'AgentShield is OFF: tool executed with NO policy check.'
    };
    const loggedRecord = auditLogger.logDecision(offEvaluation);

    try {
      // Directly execute the requested synthetic tool without policy, taint, or approval checks
      const output = await dispatchToolExecution(toolName, args, sessionTracker);
      return {
        executed: true,
        decision: 'ALLOW',
        status: 'UNSHIELDED',
        result: output,
        auditId: loggedRecord.id,
        note: 'AgentShield is OFF: tool executed with NO policy check.'
      };
    } catch (err) {
      return {
        executed: false,
        decision: 'UNSHIELDED_FAILED',
        status: 'UNSHIELDED',
        error: err.message,
        auditId: loggedRecord.id,
        note: 'AgentShield is OFF: tool execution threw an error.'
      };
    }
  }

  // 1. POLICY EVALUATION
  const evaluation = PolicyEngine.evaluateToolCall(toolName, args, sessionTracker, userContext);

  // 2. LOG TO AUDIT TRAIL
  const loggedRecord = auditLogger.logDecision(evaluation);

  // 3. DECISION ENFORCEMENT
  if (evaluation.decision === 'ALLOW') {
    try {
      const output = await dispatchToolExecution(toolName, args, sessionTracker);
      return {
        executed: true,
        decision: 'ALLOW',
        status: evaluation.status,
        result: output,
        auditId: loggedRecord.id,
        evaluation
      };
    } catch (dispatchErr) {
      return {
        executed: false,
        decision: 'ALLOW_BUT_FAILED',
        error: dispatchErr.message,
        auditId: loggedRecord.id,
        evaluation
      };
    }
  }

  if (evaluation.decision === 'REQUIRE_APPROVAL') {
    const approvalId = `appr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const pendingItem = {
      id: approvalId,
      timestamp: evaluation.timestamp,
      toolName,
      args,
      riskLevel: evaluation.riskLevel,
      ruleId: evaluation.ruleId,
      reason: evaluation.reason,
      sessionTracker,
      status: 'PENDING'
    };

    pendingApprovals.set(approvalId, pendingItem);

    return {
      executed: false,
      decision: 'REQUIRE_APPROVAL',
      status: evaluation.status,
      approvalId,
      pendingApproval: {
        id: approvalId,
        toolName,
        args,
        riskLevel: evaluation.riskLevel,
        reason: evaluation.reason
      },
      auditId: loggedRecord.id,
      evaluation
    };
  }

  // DENY or INJECT_BLOCKED: Tool execution is strictly PREVENTED
  return {
    executed: false,
    decision: 'DENY',
    status: evaluation.status,
    blockedReason: evaluation.reason,
    auditId: loggedRecord.id,
    evaluation
  };
}

