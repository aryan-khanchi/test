import express from 'express';
import crypto from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const REGISTERED_EMAIL = '24f1002157@ds.study.iitm.ac.in'.trim().toLowerCase();
const PORT = process.env.PORT || 3000;

function buildServer() {
  const server = new McpServer(
    { name: 'exam-solver', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    'solve_challenge',
    {
      title: 'Solve Challenge',
      description:
        'Reads the X-Exam-Challenge HTTP header from the current request and returns the ' +
        'first 16 hex chars of SHA-256(challenge:registeredEmail).',
      // No required properties on the input schema.
      inputSchema: {},
    },
    async (_args, extra) => {
      const headers = extra?.requestInfo?.headers || {};
      // Header keys arrive lowercased (built from the Web Headers API).
      const challenge = headers['x-exam-challenge'];

      if (!challenge || typeof challenge !== 'string') {
        return {
          content: [
            {
              type: 'text',
              text: 'ERROR: missing X-Exam-Challenge header',
            },
          ],
          isError: true,
        };
      }

      const digest = crypto
        .createHash('sha256')
        .update(`${challenge}:${REGISTERED_EMAIL}`)
        .digest('hex')
        .slice(0, 16);

      return {
        content: [{ type: 'text', text: digest }],
      };
    }
  );

  return server;
}

const app = express();
app.use(express.json());

// Stateless: build a fresh server + transport for every request so each
// tools/call reads the fresh per-call headers with no session bookkeeping.
app.post('/mcp', async (req, res) => {
  try {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on('close', () => {
      transport.close();
      server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error('MCP request error:', err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: { code: -32603, message: 'Internal server error' },
        id: null,
      });
    }
  }
});

// Stateless mode does not support GET (server-initiated SSE stream) or DELETE.
app.get('/mcp', (_req, res) => {
  res.status(405).json({
    jsonrpc: '2.0',
    error: { code: -32000, message: 'Method not allowed. This server is stateless.' },
    id: null,
  });
});

app.delete('/mcp', (_req, res) => {
  res.status(405).json({
    jsonrpc: '2.0',
    error: { code: -32000, message: 'Method not allowed. This server is stateless.' },
    id: null,
  });
});

app.get('/', (_req, res) => {
  res.send('MCP exam server is running. POST JSON-RPC to /mcp.');
});

app.listen(PORT, () => {
  console.log(`MCP server listening on port ${PORT}, endpoint: /mcp`);
});
