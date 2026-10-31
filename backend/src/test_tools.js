import { mockReadFile, mockSendEmail, mockQueryDatabase, resolveSafePath } from './mock_tools.js';
import fs from 'node:fs';

async function runTests() {
  console.log('--- RUNNING SYNTHETIC TOOLS UNIT VERIFICATION ---');
  let passed = 0;
  let failed = 0;

  // Test 1: Safe File Read
  try {
    const content = await mockReadFile('docs/q3_report.md');
    if (content.includes('Q3 Financial & Operational Summary')) {
      console.log('✅ Test 1 Passed: mockReadFile correctly reads safe docs.');
      passed++;
    } else {
      throw new Error('Content does not match expected output.');
    }
  } catch (err) {
    console.error('❌ Test 1 Failed:', err.message);
    failed++;
  }

  // Test 2: Directory Traversal Protection
  try {
    await mockReadFile('../../package.json');
    console.error('❌ Test 2 Failed: Path traversal was not blocked!');
    failed++;
  } catch (err) {
    if (err.message.includes('SECURITY_TRAVERSAL_BLOCKED')) {
      console.log('✅ Test 2 Passed: Directory traversal attempt (../../) safely blocked.');
      passed++;
    } else {
      console.error('❌ Test 2 Failed with unexpected error:', err.message);
      failed++;
    }
  }

  // Test 3: Simulated Email Dispatch to Outbox
  try {
    const res = await mockSendEmail({
      to: 'manager@company.com',
      subject: 'Unit Test Uptime Report',
      body: 'All systems 99.98% green.'
    });
    if (res.success && res.messageId) {
      console.log(`✅ Test 3 Passed: mockSendEmail wrote ${res.messageId} to mock_outbox.`);
      passed++;
    } else {
      throw new Error('Email response did not indicate success.');
    }
  } catch (err) {
    console.error('❌ Test 3 Failed:', err.message);
    failed++;
  }

  // Test 4: Database SELECT Query
  try {
    const dbRes = await mockQueryDatabase({
      query: 'SELECT name, plan FROM customers ORDER BY monthly_spend DESC'
    });
    if (dbRes.success && dbRes.rowCount === 3 && dbRes.data[0].name === 'Apex FinTech') {
      console.log('✅ Test 4 Passed: mockQueryDatabase executed in-memory SELECT correctly (3 rows).');
      passed++;
    } else {
      throw new Error(`Unexpected query result: ${JSON.stringify(dbRes)}`);
    }
  } catch (err) {
    console.error('❌ Test 4 Failed:', err.message);
    failed++;
  }

  console.log(`\nRESULTS: ${passed} passed, ${failed} failed.`);
  if (failed > 0) {
    process.exit(1);
  }
}

runTests();

