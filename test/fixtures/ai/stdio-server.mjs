// Fake MCP server over stdio for test/ai/aiStdio.test.ts. It writes tool
// entries as raw JSON text, so members such as __proto__ reach the client
// exactly as written. argv[2] is a JSON array of tool entry strings.
// Every tools/call it receives is appended to the file in argv[3].
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const tools = JSON.parse(process.argv[2] ?? "[]");
const callLog = process.argv[3];

const out = (line) => process.stdout.write(line + "\n");
createInterface({ input: process.stdin }).on("line", (text) => {
  const msg = JSON.parse(text);
  if (msg.id === undefined || msg.method === undefined) return;
  const id = JSON.stringify(msg.id);
  if (msg.method === "initialize") {
    out(`{"jsonrpc":"2.0","id":${id},"result":{"protocolVersion":${JSON.stringify(msg.params.protocolVersion)},"capabilities":{"tools":{}},"serverInfo":{"name":"stdio-fake","version":"1"}}}`);
  } else if (msg.method === "tools/list") {
    out(`{"jsonrpc":"2.0","id":${id},"result":{"tools":[${tools.join(",")}]}}`);
  } else if (msg.method === "tools/call") {
    if (callLog) appendFileSync(callLog, msg.params.name + "\n");
    out(`{"jsonrpc":"2.0","id":${id},"result":{"content":[{"type":"text","text":"ok ${msg.params.name}"}]}}`);
  } else {
    out(`{"jsonrpc":"2.0","id":${id},"error":{"code":-32601,"message":"Method not found"}}`);
  }
});
