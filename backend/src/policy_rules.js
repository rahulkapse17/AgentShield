/**
 * AgentShield (PS-01) - Policy Ruleset & Permission Matrix
 * Establishes explicit boundaries for all tools, paths, and argument patterns.
 */

export const DECISIONS = {
  ALLOW: 'ALLOW',
  DENY: 'DENY',
  REQUIRE_APPROVAL: 'REQUIRE_APPROVAL'
};

export const RISK_LEVELS = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
};

// Explicitly registered tools in the agent's permission profile
export const REGISTERED_TOOLS = new Set([
  'read_file',
  'send_email',
  'query_database'
]);

/**
 * Determines whether a tool invocation is risky under tainted session containment.
 * Risky: read_file on secrets/ or config/, send_email (any address), mutating SQL, unregistered tools.
 * Safe: read_file on docs/*, read-only SELECT queries.
 */
export function isRiskyToolCall(toolName, args = {}) {
  // 1. Unregistered tools are always risky
  if (!REGISTERED_TOOLS.has(toolName)) {
    return true;
  }

  // 2. read_file on secrets/ or config/ (or traversal)
  if (toolName === 'read_file') {
    const rawPath = String(args.path || args.filePath || '').trim().toLowerCase();
    const normalized = rawPath.replace(/^[/\\]+/, '');
    if (normalized.includes('..') || normalized.startsWith('secrets/') || normalized.startsWith('config/')) {
      return true;
    }
    // Safe calls: read_file on docs/*
    if (normalized.startsWith('docs/')) {
      return false;
    }
    return true;
  }

  // 3. send_email (any address is risky when untrusted content is present)
  if (toolName === 'send_email') {
    return true;
  }

  // 4. query_database with mutating verbs
  if (toolName === 'query_database') {
    const query = String(args.query || '').trim();
    const isMutating = /\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|CREATE)\b/i.test(query);
    if (isMutating) {
      return true;
    }
    // Safe calls: SELECT queries
    if (/^SELECT\b/i.test(query)) {
      return false;
    }
    return true;
  }

  return true;
}

/**
 * Evaluates static policy matrix against a requested tool and its arguments.
 */
export function evaluateStaticPolicy(toolName, args = {}) {
  // 1. Tool Registration Check (Fail-closed on unregistered tools)
  if (!REGISTERED_TOOLS.has(toolName)) {
    return {
      decision: DECISIONS.DENY,
      riskLevel: RISK_LEVELS.CRITICAL,
      ruleId: 'RULE_UNREGISTERED_TOOL',
      reason: `Tool '${toolName}' is not permitted in the agent's active permission profile.`
    };
  }

  // 2. Specific Policy for read_file
  if (toolName === 'read_file') {
    const rawPath = String(args.path || args.filePath || '').trim().toLowerCase();
    const normalized = rawPath.replace(/^[/\\]+/, '');

    // Directory traversal guard
    if (normalized.includes('..')) {
      return {
        decision: DECISIONS.DENY,
        riskLevel: RISK_LEVELS.CRITICAL,
        ruleId: 'RULE_PATH_TRAVERSAL',
        reason: "Path traversal escape pattern ('..') detected."
      };
    }

    // Secrets zone: Strictly DENY
    if (normalized.startsWith('secrets/') || normalized.startsWith('/secrets/')) {
      return {
        decision: DECISIONS.DENY,
        riskLevel: RISK_LEVELS.CRITICAL,
        ruleId: 'RULE_DENY_SECRETS',
        reason: "Direct access to confidential credentials and keys in '/secrets/' is strictly forbidden."
      };
    }

    // Config zone: REQUIRE_APPROVAL
    if (normalized.startsWith('config/') || normalized.startsWith('/config/')) {
      return {
        decision: DECISIONS.REQUIRE_APPROVAL,
        riskLevel: RISK_LEVELS.MEDIUM,
        ruleId: 'RULE_APPROVAL_CONFIG',
        reason: "Access to system configuration in '/config/' requires human supervisor approval."
      };
    }

    // Docs zone: ALLOW
    if (normalized.startsWith('docs/') || normalized.startsWith('/docs/')) {
      return {
        decision: DECISIONS.ALLOW,
        riskLevel: RISK_LEVELS.LOW,
        ruleId: 'RULE_ALLOW_DOCS',
        reason: "Resource located in whitelisted public workspace '/docs/'."
      };
    }

    // Default Fail-Closed for any other path
    return {
      decision: DECISIONS.DENY,
      riskLevel: RISK_LEVELS.HIGH,
      ruleId: 'RULE_PATH_OUT_OF_BOUNDS',
      reason: `Requested path '${rawPath}' is outside authorized directory scopes.`
    };
  }

  // 3. Specific Policy for send_email
  if (toolName === 'send_email') {
    const recipient = String(args.to || '').trim().toLowerCase();

    if (!recipient) {
      return {
        decision: DECISIONS.DENY,
        riskLevel: RISK_LEVELS.MEDIUM,
        ruleId: 'RULE_EMAIL_MISSING_RECIPIENT',
        reason: 'Email recipient field is missing or empty.'
      };
    }

    // High-impact outbound communication: REQUIRE_APPROVAL for all valid emails
    return {
      decision: DECISIONS.REQUIRE_APPROVAL,
      riskLevel: RISK_LEVELS.MEDIUM,
      ruleId: 'RULE_APPROVAL_EMAIL',
      reason: `Outbound email to '${recipient}' requires human supervisor approval.`
    };
  }

  // 4. Specific Policy for query_database
  if (toolName === 'query_database') {
    const query = String(args.query || '').trim();

    // Check for mutating operations (DROP, DELETE, UPDATE, INSERT, ALTER, TRUNCATE)
    const isMutating = /\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|CREATE)\b/i.test(query);

    if (isMutating) {
      return {
        decision: DECISIONS.DENY,
        riskLevel: RISK_LEVELS.CRITICAL,
        ruleId: 'RULE_DENY_MUTATING_SQL',
        reason: 'Mutating database operations (INSERT, UPDATE, DELETE, DROP) are strictly prohibited.'
      };
    }

    // Read-only SELECT query: ALLOW
    if (/^SELECT\b/i.test(query)) {
      return {
        decision: DECISIONS.ALLOW,
        riskLevel: RISK_LEVELS.LOW,
        ruleId: 'RULE_ALLOW_SELECT_SQL',
        reason: 'Read-only SELECT query is permitted by database policy.'
      };
    }

    // Fail-closed for non-standard queries
    return {
      decision: DECISIONS.DENY,
      riskLevel: RISK_LEVELS.HIGH,
      ruleId: 'RULE_DENY_UNRECOGNIZED_SQL',
      reason: 'SQL statement does not match permitted read-only grammar.'
    };
  }

  // Fallback Fail-Closed
  return {
    decision: DECISIONS.DENY,
    riskLevel: RISK_LEVELS.CRITICAL,
    ruleId: 'RULE_FAIL_CLOSED_DEFAULT',
    reason: 'Policy evaluation was inconclusive. Defaulting to fail-closed DENY.'
  };
}

