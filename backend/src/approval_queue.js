/**
 * AgentShield (PS-01) - Human-in-the-Loop (HITL) Approval Manager
 * Manages privileged action queue, blast-radius risk evaluation, and human approvals/rejections.
 */

import { pendingApprovals } from './interceptor.js';
import { auditLogger } from './audit_logger.js';
import { mockReadFile, mockSendEmail, mockQueryDatabase } from './mock_tools.js';

/**
 * Calculates human-readable blast-radius and impact summary for a pending action.
 */
export function calculateBlastRadius(toolName, args = {}) {
  if (toolName === 'read_file') {
    const path = String(args.path || args.filePath || '');
    if (path.includes('config')) {
      return {
        scope: 'INFRASTRUCTURE_CONFIGURATION',
        impact: 'Exposes server network bindings, database ports, and pool limits to the agent.',
        recommendation: 'Verify whether agent needs infrastructure configuration to answer user query.'
      };
    }
  }

  if (toolName === 'send_email') {
    const recipient = String(args.to || '');
    return {
      scope: 'COMMUNICATIONS',
      impact: `Dispatches message to recipient '${recipient}'. Once sent, email cannot be recalled.`,
      recommendation: 'Inspect email subject and body preview before releasing.'
    };
  }

  if (toolName === 'query_database') {
    return {
      scope: 'PERSISTENCE_LAYER',
      impact: 'Reads or modifies tables in the persistent database.',
      recommendation: 'Ensure query contains read-only constraints.'
    };
  }

  return {
    scope: 'GENERAL_SYSTEM',
    impact: `Action invokes tool '${toolName}' on target resource.`,
    recommendation: 'Review tool arguments for safety.'
  };
}

export class ApprovalManager {
  /**
   * Retrieves all currently pending approval requests enriched with blast-radius data.
   */
  static listPending() {
    const list = [];
    for (const [id, item] of pendingApprovals.entries()) {
      if (item.status === 'PENDING') {
        list.push({
          id,
          timestamp: item.timestamp,
          toolName: item.toolName,
          args: item.args,
          riskLevel: item.riskLevel,
          ruleId: item.ruleId,
          reason: item.reason,
          blastRadius: calculateBlastRadius(item.toolName, item.args)
        });
      }
    }
    return list;
  }

  /**
   * Resolves a pending approval with either 'APPROVE' or 'REJECT'.
   */
  static async resolve(approvalId, action, reviewer = 'Security Supervisor') {
    const item = pendingApprovals.get(approvalId);
    if (!item) {
      throw new Error(`APPROVAL_NOT_FOUND: No pending approval with ID '${approvalId}'.`);
    }

    if (item.status !== 'PENDING') {
      throw new Error(`APPROVAL_ALREADY_RESOLVED: Approval '${approvalId}' is already '${item.status}'.`);
    }

    if (action === 'APPROVE') {
      item.status = 'APPROVED';
      item.resolvedAt = new Date().toISOString();
      item.reviewer = reviewer;

      // Execute the previously intercepted tool
      let output;
      if (item.toolName === 'read_file') {
        output = await mockReadFile(item.args.path || item.args.filePath);
      } else if (item.toolName === 'send_email') {
        output = await mockSendEmail(item.args);
      } else if (item.toolName === 'query_database') {
        output = await mockQueryDatabase(item.args);
      }

      // Log manual human approval in the tamper-evident audit trail
      auditLogger.logDecision({
        toolName: item.toolName,
        args: item.args,
        provenance: `human_approved:${reviewer}`,
        decision: 'ALLOW',
        status: 'ALLOWED',
        riskLevel: item.riskLevel,
        ruleId: 'HUMAN_SUPERVISOR_OVERRIDE_APPROVE',
        reason: `High-impact action confirmed and authorized by ${reviewer}.`
      });

      return {
        success: true,
        action: 'APPROVED',
        approvalId,
        toolOutput: output
      };
    }

    if (action === 'REJECT') {
      item.status = 'REJECTED';
      item.resolvedAt = new Date().toISOString();
      item.reviewer = reviewer;

      // Log manual human rejection in the audit trail
      auditLogger.logDecision({
        toolName: item.toolName,
        args: item.args,
        provenance: `human_rejected:${reviewer}`,
        decision: 'DENY',
        status: 'DENIED',
        riskLevel: item.riskLevel,
        ruleId: 'HUMAN_SUPERVISOR_OVERRIDE_REJECT',
        reason: `High-impact action explicitly rejected by ${reviewer}.`
      });

      return {
        success: true,
        action: 'REJECTED',
        approvalId,
        reason: `Action rejected by ${reviewer}. Execution halted.`
      };
    }

    throw new Error(`INVALID_RESOLUTION_ACTION: Action must be 'APPROVE' or 'REJECT'.`);
  }
}

