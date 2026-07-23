import assert from "node:assert/strict";
import * as http from "node:http";
import { test } from "node:test";

import { InferenceContextLengthError } from "../antares/inference/backend";
import { RemoteInferenceBackend } from "../antares/inference/remote";

interface MockServer {
  port: number;
  paths: string[];
  bodies: string[];
  close: () => Promise<void>;
}

function startServer(handler: http.RequestListener): Promise<MockServer> {
  const paths: string[] = [];
  const bodies: string[] = [];
  const server = http.createServer((req, res) => {
    paths.push(req.url ?? "");
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      bodies.push(body);
      handler(req, res);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({
        port,
        paths,
        bodies,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

async function collect(iterable: AsyncIterable<string>): Promise<string> {
  let out = "";
  for await (const chunk of iterable) {
    out += chunk;
  }
  return out;
}

test("chat API streams delta content from /v1/chat/completions", async () => {
  const server = await startServer((_req, res) => {
    const parts = ["Hello", ", ", "world"];
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    for (const p of parts) {
      res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: p } }] })}\n\n`);
    }
    res.write("data: [DONE]\n\n");
    res.end();
  });
  try {
    const backend = new RemoteInferenceBackend({
      modelId: "m",
      endpoint: `http://127.0.0.1:${server.port}/v1`,
      useCompletionsApi: false,
    });
    const text = await collect(backend.streamGenerate([{ role: "user", content: "hi" }]));
    assert.equal(text, "Hello, world");
    assert.deepEqual(server.paths, ["/v1/chat/completions"]);
  } finally {
    await server.close();
  }
});

test("completions API streams text content from /v1/completions with a prompt", async () => {
  const server = await startServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.write(`data: ${JSON.stringify({ choices: [{ text: "OK" }] })}\n\n`);
    res.write("data: [DONE]\n\n");
    res.end();
  });
  try {
    const backend = new RemoteInferenceBackend({
      modelId: "m",
      endpoint: `http://127.0.0.1:${server.port}/v1/completions`,
    });
    const text = await collect(backend.streamGenerate([{ role: "user", content: "hi" }]));
    assert.equal(text, "OK");
    assert.deepEqual(server.paths, ["/v1/completions"]);
    assert.ok(server.bodies[0].includes("prompt"));
  } finally {
    await server.close();
  }
});

test("context-length rejection raises InferenceContextLengthError", async () => {
  const server = await startServer((_req, res) => {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "This model's maximum context length is 4096 tokens" }));
  });
  try {
    const backend = new RemoteInferenceBackend({
      modelId: "m",
      endpoint: `http://127.0.0.1:${server.port}/v1`,
      useCompletionsApi: false,
      retryCount: 1,
    });
    await assert.rejects(
      () => collect(backend.streamGenerate([{ role: "user", content: "hi" }])),
      InferenceContextLengthError
    );
  } finally {
    await server.close();
  }
});
