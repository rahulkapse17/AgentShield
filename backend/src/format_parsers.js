/**
 * AgentShield (PS-01) - Universal Document & Multi-Format Text Extractor
 * Normalizes rich documents, code, and web markup into inspectable text streams
 * for the Policy Enforcement Point (PEP).
 */

import path from 'node:path';

/**
 * Extracts clean inspectable text and flags hidden injection vectors
 * based on file extension.
 *
 * @param {string} fileName - Original file name with extension
 * @param {string|Buffer} content - Raw file data
 * @returns {object} { text, format, hiddenVectorsFound, metadata }
 */
export function extractDocumentText(fileName, content) {
  const ext = path.extname(fileName).toLowerCase();
  const rawString = typeof content === 'string' ? content : content.toString('utf-8');
  let extractedText = rawString;
  let hiddenVectorsFound = [];
  let format = 'PLAINTEXT';

  switch (ext) {
    // 1. HTML / XML Web Markup
    case '.html':
    case '.htm':
    case '.xml': {
      format = ext === '.xml' ? 'XML_MARKUP' : 'HTML_WEB_PAGE';
      
      // Inspect for hidden comments used in prompt injections
      const commentMatches = rawString.match(/<!--([\s\S]*?)-->/g);
      if (commentMatches) {
        hiddenVectorsFound.push(`HTML comments detected (${commentMatches.length} comment blocks)`);
      }

      // Inspect for hidden CSS style injections (display:none or visibility:hidden)
      const hiddenStyleMatches = rawString.match(/<[^>]+style=["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi);
      if (hiddenStyleMatches) {
        hiddenVectorsFound.push(`Hidden CSS elements detected (display:none / visibility:hidden)`);
      }

      // Strip HTML tags for clean agent reasoning, preserving comment contents for injection scanning
      extractedText = rawString
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove scripts
        .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')   // Remove stylesheets
        .replace(/<[^>]+>/g, ' ')                                          // Strip tags
        .replace(/\s+/g, ' ')                                              // Normalize whitespace
        .trim();
      break;
    }

    // 2. Code & Script Formats
    case '.py':
    case '.js':
    case '.ts':
    case '.sh':
    case '.sql':
    case '.yaml':
    case '.yml': {
      format = `CODE_SCRIPT_${ext.substring(1).toUpperCase()}`;

      // Check for destructive code snippets
      if (/\b(rm\s+-rf|os\.system|subprocess|eval\(|DROP\s+TABLE|DELETE\s+FROM)\b/i.test(rawString)) {
        hiddenVectorsFound.push(`Potentially destructive code commands detected in ${ext} script`);
      }
      extractedText = rawString;
      break;
    }

    // 3. Portable Document Format (PDF) Text Objects Extraction
    case '.pdf': {
      format = 'PDF_DOCUMENT';
      
      // Extract text enclosed in PDF Text Object blocks: BT ... ET with (text) Tj or [(text)] TJ
      const textBlocks = [];
      const tjRegex = /\(([^)]+)\)\s*(?:Tj|'|")/g;
      let match;
      while ((match = tjRegex.exec(rawString)) !== null) {
        textBlocks.push(match[1]);
      }

      if (textBlocks.length > 0) {
        extractedText = textBlocks.join(' ');
      } else {
        // Fallback: clean ASCII printable characters from stream
        extractedText = rawString.replace(/[^\x20-\x7E\r\n\t]/g, ' ').replace(/\s+/g, ' ').trim();
      }
      break;
    }

    // 4. Office XML Documents (DOCX / XLSX)
    case '.docx':
    case '.xlsx': {
      format = `OFFICE_${ext.substring(1).toUpperCase()}`;
      // Extract XML string fragments enclosed in <w:t> or <t> text tags
      const xmlTextMatches = rawString.match(/<(?:\w+:)?t[^>]*>([^<]+)<\/(?:\w+:)?t>/g);
      if (xmlTextMatches) {
        extractedText = xmlTextMatches.map(m => m.replace(/<[^>]+>/g, '')).join(' ');
      } else {
        extractedText = rawString.replace(/[^\x20-\x7E\r\n\t]/g, ' ').replace(/\s+/g, ' ').trim();
      }
      break;
    }

    // 5. Standard Data & Tabular formats (.txt, .md, .json, .csv, .log, .env)
    case '.json':
      format = 'JSON_STRUCTURED';
      extractedText = rawString;
      break;
    case '.csv':
      format = 'CSV_TABULAR';
      extractedText = rawString;
      break;
    case '.env':
      format = 'ENVIRONMENT_CONFIG';
      extractedText = rawString;
      break;
    case '.md':
      format = 'MARKDOWN_DOC';
      extractedText = rawString;
      break;
    default:
      format = 'TEXT_STREAM';
      extractedText = rawString;
      break;
  }

  return {
    format,
    originalLength: rawString.length,
    extractedLength: extractedText.length,
    text: extractedText,
    hiddenVectorsFound
  };
}

