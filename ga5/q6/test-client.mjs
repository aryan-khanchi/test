import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import crypto from 'node:crypto';

const EMAIL = '24f1002157@ds.study.iitm.ac.in';

async function main() {
  const transport = new StreamableHTTPClientTransport(new URL('http://localhost:3000/mcp'), {
    requestInit: { headers: {} },
  });
  const client = new Client({ name: 'grader-sim', version: '1.0.0' });
  await client.connect(transport);

  const tools = await client.listTools();
  console.log('tools/list ->', JSON.stringify(tools, null, 2));

  const toolNames = tools.tools.map((t) => t.name);
  if (!toolNames.includes('solve_challenge')) {
    throw new Error('solve_challenge tool NOT found!');
  }

  for (let i = 0; i < 5; i++) {
    const challenge = crypto.randomBytes(16).toString('hex');
    // Fresh per-call headers, exactly like the grader claims to send.
    // The transport re-reads this object on every request (see _commonHeaders()).
    transport._requestInit.headers = {
      'X-Exam-Challenge': challenge,
      'X-Exam-Timestamp': String(Date.now()),
      'X-Exam-Signature': 'deadbeef', // unscored/optional per spec
    };

    const result = await client.callTool({ name: 'solve_challenge', arguments: {} });
    const got = result.content[0].text;
    const expected = crypto
      .createHash('sha256')
      .update(`${challenge}:${EMAIL}`)
      .digest('hex')
      .slice(0, 16);

    const ok = got === expected;
    console.log(`call ${i + 1}: challenge=${challenge} got=${got} expected=${expected} -> ${ok ? 'OK' : 'FAIL'}`);
    if (!ok) process.exitCode = 1;
  }

  await client.close();
}

main().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
