/**
 * AgentShield (PS-01) - REST API & Mission Control Server
 * Powers the real-time security dashboard and policy enforcement endpoints.
 */

import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCENARIO_DEFINITIONS, runScenario } from './scenario_runner.js';
import { auditLogger } from './audit_logger.js';
import { ApprovalManager } from './approval_queue.js';
import { interceptToolCall } from './interceptor.js';
import { SessionProvenanceTracker } from './taint_tracker.js';

import { shieldState } from './shield_state.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'AgentShield Policy Enforcement Point (PEP)',
    timestamp: new Date().toISOString()
  });
});

// Shield State Endpoints (ON/OFF Demonstration Mode)
app.get('/api/shield', (req, res) => {
  res.json({
    enabled: shieldState.enabled
  });
});

app.post('/api/shield', (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({
      error: 'Invalid input: "enabled" must be an actual boolean (true or false).'
    });
  }

  shieldState.enabled = enabled;
  res.json({
    enabled: shieldState.enabled
  });
});

// List all scenarios
app.get('/api/scenarios', (req, res) => {
  res.json({ scenarios: SCENARIO_DEFINITIONS });
});

// Run a specific scenario
app.post('/api/scenarios/run', async (req, res) => {
  try {
    const { scenarioId } = req.body;
    if (!scenarioId) {
      return res.status(400).json({ error: 'scenarioId is required' });
    }

    const result = await runScenario(scenarioId);
    res.json({
      success: true,
      result,
      stats: auditLogger.getAuditStats()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Custom Prompt Runner
app.post('/api/agent/prompt', async (req, res) => {
  try {
    const { prompt, bypassSecurity } = req.body;
    if (!prompt) {
      return res.status(400).json({ error: 'prompt is required' });
    }

    const { hybridSearchScan } = await import('./hybrid_search.js');
    const hybridScan = hybridSearchScan(prompt);

    const { AgentSimulator } = await import('./agent_core.js');
    const agent = new AgentSimulator();
    const session = new SessionProvenanceTracker(`sess_${Date.now()}`, prompt);

    const plan = await agent.planAction(prompt);
    const interceptResult = await interceptToolCall({
      toolName: plan.toolCall.toolName,
      args: plan.toolCall.args,
      sessionTracker: session,
      bypassSecurity: !!bypassSecurity
    });

    res.json({
      prompt,
      hybridScan,
      plan,
      interceptResult,
      stats: auditLogger.getAuditStats()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Upload and Analyze Custom Document (Multi-Format Support)
app.post('/api/upload-and-analyze', async (req, res) => {
  try {
    const { fileName, fileContent } = req.body;
    if (!fileName || typeof fileContent !== 'string') {
      return res.status(400).json({ error: 'fileName and fileContent are required' });
    }

    const fs = await import('node:fs');
    const { extractDocumentText } = await import('./format_parsers.js');

    const safeFileName = path.basename(fileName).replace(/[^a-zA-Z0-9._-]/g, '_');
    const uploadDir = path.join(__dirname, '..', 'synthetic_env', 'docs');
    const filePath = path.join(uploadDir, safeFileName);

    // Save raw file in /docs/
    fs.writeFileSync(filePath, fileContent, 'utf-8');

    // Extract text and uncover hidden vectors across PDF, DOCX, HTML, Code, etc.
    const parsedDoc = extractDocumentText(safeFileName, fileContent);
    const contentToAnalyze = parsedDoc.text + (parsedDoc.hiddenVectorsFound.length > 0 ? ` [VECTORS: ${parsedDoc.hiddenVectorsFound.join(', ')}]` : '');

    const prompt = `Inspect and process uploaded ${parsedDoc.format} document docs/${safeFileName}`;
    const session = new SessionProvenanceTracker(`sess_upload_${Date.now()}`, prompt);

    // Ingest and scan for indirect prompt injection
    const ingestOutcome = session.ingestContent(`docs/${safeFileName}`, contentToAnalyze);

    const { AgentSimulator } = await import('./agent_core.js');
    const agent = new AgentSimulator();

    // Simulated Vulnerable Agent planning: builds tool call directly from the document's
    // extracted text, INDEPENDENT of whether the hybrid detector flagged the file.
    const gulliblePlan = agent.extractGulliblePlan(contentToAnalyze);
    let plan;
    if (gulliblePlan) {
      plan = gulliblePlan;
    } else {
      plan = {
        thought: `Simulated vulnerable agent found no actionable directives inside ${safeFileName} (${parsedDoc.format}). Reading and summarizing content safely.`,
        toolCall: {
          toolName: 'read_file',
          args: { path: `docs/${safeFileName}` }
        }
      };
    }

    // Pass through PEP Interceptor
    const interceptResult = await interceptToolCall({
      toolName: plan.toolCall.toolName,
      args: plan.toolCall.args,
      sessionTracker: session
    });

    res.json({
      fileName: safeFileName,
      parsedDoc,
      ingestOutcome,
      plan,
      interceptResult,
      stats: auditLogger.getAuditStats()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Audit Trail Endpoints
app.get('/api/audit', (req, res) => {
  res.json({
    logs: auditLogger.getAuditLogs(),
    stats: auditLogger.getAuditStats()
  });
});

app.get('/api/audit/stats', (req, res) => {
  res.json({ stats: auditLogger.getAuditStats() });
});

app.get('/api/audit/verify', (req, res) => {
  const verification = auditLogger.verifyAuditIntegrity();
  res.json({
    ...verification,
    verifiedAt: new Date().toISOString()
  });
});

app.post('/api/audit/clear', (req, res) => {
  auditLogger.clear();
  res.json({ success: true, message: 'Audit log reset.' });
});

// Pending Approvals Endpoints
app.get('/api/approvals', (req, res) => {
  res.json({ pending: ApprovalManager.listPending() });
});

app.post('/api/approvals/:id/resolve', async (req, res) => {
  try {
    const { id } = req.params;
    const { action, reviewer } = req.body; // action: 'APPROVE' or 'REJECT'
    const outcome = await ApprovalManager.resolve(id, action, reviewer || 'Security Operator');
    res.json({
      success: true,
      outcome,
      stats: auditLogger.getAuditStats()
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.listen(PORT, HOST, () => {
  console.log(`========================================================`);
  console.log(`🛡️  AGENTSHIELD SERVER ONLINE`);
  console.log(`📡  Endpoint: http://${HOST}:${PORT}`);
  console.log(`🔒  PEP Mode: FAIL-CLOSED ZERO-TRUST`);
  console.log(`========================================================`);
});
