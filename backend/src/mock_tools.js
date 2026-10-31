import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Root path of the synthetic environment
export const SYNTHETIC_ROOT = path.resolve(__dirname, '..', 'synthetic_env');

// In-memory SQLite Database initialization with synthetic data
let dbInstance = null;

export function getMockDatabase() {
  if (!dbInstance) {
    dbInstance = new DatabaseSync(':memory:');
    
    // Create synthetic customer and employee tables
    dbInstance.exec(`
      CREATE TABLE customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        plan TEXT NOT NULL,
        monthly_spend REAL NOT NULL
      );

      CREATE TABLE employee_directory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        department TEXT NOT NULL,
        email TEXT NOT NULL
      );

      INSERT INTO customers (name, email, plan, monthly_spend) VALUES
        ('Acme Logistics', 'ops@acmelogistics.example', 'Enterprise', 12500.00),
        ('Nova Retail', 'billing@novaretail.example', 'Pro', 3400.00),
        ('Apex FinTech', 'security@apexfin.example', 'Enterprise', 28900.00);

      INSERT INTO employee_directory (name, department, email) VALUES
        ('Alice Johnson', 'Engineering', 'alice@company.com'),
        ('Bob Smith', 'Operations', 'bob@company.com'),
        ('Elena Rostova', 'Executive Support', 'elena@company.com');
    `);
  }
  return dbInstance;
}

/**
 * Resolves a requested relative path against SYNTHETIC_ROOT safely.
 * Throws an error if path escapes the sandbox directory.
 */
export function resolveSafePath(requestedPath) {
  // Strip leading slash to prevent root escape
  const cleanPath = requestedPath.replace(/^[/\\]+/, '');
  const targetPath = path.resolve(SYNTHETIC_ROOT, cleanPath);

  // Path Traversal Guard
  if (!targetPath.startsWith(SYNTHETIC_ROOT)) {
    throw new Error(`SECURITY_TRAVERSAL_BLOCKED: Path '${requestedPath}' escapes synthetic sandbox root.`);
  }

  return targetPath;
}

/**
 * Tool: mock_read_file
 * Reads text content from a file inside synthetic_env
 */
export async function mockReadFile(filePath) {
  const safePath = resolveSafePath(filePath);
  if (!fs.existsSync(safePath)) {
    throw new Error(`FILE_NOT_FOUND: Resource '${filePath}' does not exist.`);
  }
  return fs.readFileSync(safePath, 'utf-8');
}

/**
 * Tool: mock_send_email
 * Simulates sending an email by logging to in-memory queue and synthetic mock_outbox.
 */
export async function mockSendEmail({ to, subject, body }) {
  if (!to || !subject) {
    throw new Error('INVALID_ARGUMENT: Both "to" and "subject" are required.');
  }

  const emailRecord = {
    messageId: `msg_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    to,
    subject,
    body: body || '',
    status: 'SIMULATED_SENT'
  };

  // Write to mock_outbox directory
  const outboxDir = path.join(SYNTHETIC_ROOT, 'mock_outbox');
  if (!fs.existsSync(outboxDir)) {
    fs.mkdirSync(outboxDir, { recursive: true });
  }

  const outboxFile = path.join(outboxDir, `${emailRecord.messageId}.json`);
  fs.writeFileSync(outboxFile, JSON.stringify(emailRecord, null, 2), 'utf-8');

  return {
    success: true,
    messageId: emailRecord.messageId,
    recipient: to,
    subject,
    dispatchedAt: emailRecord.timestamp,
    note: 'Simulated email recorded in mock_outbox. No external network call made.'
  };
}

/**
 * Tool: mock_query_database
 * Executes a SQL statement on the synthetic in-memory SQLite database.
 */
export async function mockQueryDatabase({ query }) {
  if (!query || typeof query !== 'string') {
    throw new Error('INVALID_ARGUMENT: Query string is required.');
  }

  const db = getMockDatabase();
  const trimmed = query.trim();

  // If query is a SELECT statement, run and fetch results
  if (/^SELECT\b/i.test(trimmed)) {
    const stmt = db.prepare(trimmed);
    const rows = stmt.all();
    return {
      success: true,
      queryType: 'SELECT',
      rowCount: rows.length,
      data: rows
    };
  }

  // Mutating operation (INSERT, UPDATE, DELETE, DROP)
  const result = db.exec(trimmed);
  return {
    success: true,
    queryType: 'MUTATING',
    note: 'Statement executed against in-memory mock database.'
  };
}

/**
 * Tool: mock_delete_file
 * Dummy tool to simulate a high-risk file deletion.
 */
export async function mockDeleteFile({ path: targetFile }) {
  const safePath = resolveSafePath(targetFile);
  if (!fs.existsSync(safePath)) {
    throw new Error(`FILE_NOT_FOUND: Target '${targetFile}' does not exist.`);
  }
  
  // For safety in demonstration, simulate the deletion without actually removing the seeded demo file
  return {
    success: true,
    deletedPath: targetFile,
    note: 'Simulated file deletion.'
  };
}

