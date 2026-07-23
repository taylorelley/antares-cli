# Antares Security Scanner for VS Code

Run the [Antares](https://github.com/taylorelley/antares-cli) CWE vulnerability-localization
agent directly in VS Code. Antares reads your code (read-only) and reports a ranked list of
files that likely contain a given class of vulnerability (CWE), surfaced in the **Problems
panel** and a dedicated **Antares** view.

The extension is a **fully native TypeScript reimplementation** of the Antares agent — it
requires **no Python, no external tools, and no runtime dependencies**. The model is
configurable and works against **OpenAI-API-compatible** servers and **Ollama**, including
a local Ollama instance out of the box.

## How it works

Everything runs inside the extension. Scans execute in a **Node worker thread** so the
editor stays responsive; the worker streams progress, findings, and the final result back
to the UI. The agent, its read-only command **sandbox**, the CWE **auto-selection engine**,
and the bundled MITRE CWE catalog (969 entries) all ship with the extension.

```
VS Code extension  ──worker thread──▶  native Antares engine
      ▲                                       │
      └──────────── progress / findings ──────┘
                     (streamed events)
```

The agent talks to your model over the OpenAI SSE streaming API. Nothing else leaves your
machine — the sandbox reads files locally and never writes, spawns processes, or hits the
network.

## Requirements

- **VS Code 1.85+** (ships a recent Node runtime).
- Access to an inference endpoint:
  - **Ollama**: run `ollama serve` and pull a model (e.g. `ollama pull qwen2.5-coder`).
  - **OpenAI-compatible** server (vLLM, LM Studio, a gateway, etc.).
  - **vLLM-hosted Antares checkpoints** for the tested `/v1/completions` path.

That's it — there is no Python or CLI to install.

## Quick start (Ollama)

1. Install and start Ollama, then pull a code model: `ollama pull qwen2.5-coder`.
2. In VS Code settings set **Antares: Model** to the model id (e.g. `qwen2.5-coder`). The
   default provider is **Ollama** and the endpoint defaults to `http://localhost:11434/v1`.
3. Run **Antares: Auto-Sweep Folder for Vulnerabilities** from the Command Palette, or
   right-click a folder in the Explorer → **Antares: Scan Folder for CWE…**.
4. Findings appear in the **Problems panel** and the **Antares** activity-bar view.

## Commands

| Command | Description |
| --- | --- |
| `Antares: Scan Folder for CWE…` | Prompts for CWE IDs and scans a folder for exactly those classes. |
| `Antares: Auto-Sweep Folder for Vulnerabilities` | Profiles the repo, auto-selects likely CWE classes, and scans them in parallel. |
| `Antares: Set API Key` | Stores an API key in VS Code SecretStorage (sent as a bearer token). |
| `Antares: Clear API Key` | Removes the stored API key. |
| `Antares: Show Last Report (JSON)` | Opens the most recent result as JSON. |
| `Antares: Save Report…` | Writes the last result as JSON, Markdown, or SARIF 2.1.0. |
| `Antares: Clear Results` | Clears diagnostics and the results view. |

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `antares.provider` | `ollama` | Connection preset: `ollama`, `openai-compatible`, `vllm`, or `custom`. |
| `antares.endpoint` | `""` | Inference base URL. Empty uses the provider default (Ollama only). |
| `antares.model` | `""` | Served model id — must match the endpoint exactly. |
| `antares.apiStyle` | `auto` | `auto`, `chat` (`/v1/chat/completions`), or `completions` (`/v1/completions`). |
| `antares.toolBudget` | `0` | Tool-call budget per scan (`0` = Antares default of 15). |
| `antares.sweep.workers` | `4` | Parallel CWE workers for Auto-Sweep. |
| `antares.sweep.maxCwes` | `8` | Max CWE classes Auto-Sweep selects. |
| `antares.diagnosticsSeverity` | `warning` | Severity used for findings in the Problems panel. |

### API style and providers

Antares talks to two OpenAI-compatible shapes:

- **`chat`** → `POST /v1/chat/completions` — used by **Ollama** and most OpenAI-compatible
  servers (default for the `ollama`/`openai-compatible` presets).
- **`completions`** → `POST /v1/completions` with a Granite chat template — the tested path
  for **vLLM-hosted Antares checkpoints** (default for the `vllm` preset).

When `antares.apiStyle` is `auto` the style is derived from the provider; set it explicitly
to override.

### API key

Keyless servers such as a local Ollama need no key. For hosted endpoints, run **Antares:
Set API Key**; the key is stored in VS Code SecretStorage and passed to the engine
in-process — it is never written to settings or a command line.

## Fidelity notes

This extension is a faithful port of the Python `antares-cli` reference:

- The agent loop, streaming tool-call parser, system prompt, Granite template, and CWE
  auto-selection are verified against the Python implementation (byte-identical prompt,
  exact ordered CWE selection on fixture repos).
- The read-only command **sandbox** reproduces the Python allow-list/policy exactly
  (accept/reject decisions and error messages match). The allow-listed commands
  (`grep`, `find`, `cat`, `sed -n`, `ls`, `wc`, …) are re-implemented in pure TypeScript
  over the workspace, so they are cross-platform and need no system binaries; their output
  is functionally correct rather than byte-identical to GNU coreutils.

## Development

```bash
npm install
npm run compile        # bundle to dist/ (extension.js + worker.js) via esbuild
npm run check-types    # tsc --noEmit
npm run test-unit      # node --test parity + behavior tests (no external deps)
npm run vsix           # produce antares-vscode-<version>.vsix
```

Press **F5** to launch an Extension Development Host. Install the packaged build with
`code --install-extension antares-vscode-0.2.0.vsix`.

The bundled CWE data and the generated selection rule tables live under `data/`. Regenerate
the selection tables from the Python reference with
`uv run python tools/gen-selection-tables.py` (dev-only; requires the `antares-cli` repo).

### Git hook (auto-build the VSIX) & CI

A pre-commit hook rebuilds and type-checks the VSIX whenever extension source is staged;
enable it once per clone with `git config core.hooksPath .githooks`. CI
(`.github/workflows/vscode-extension.yml`) builds, tests, and packages on push/PR, and
publishes a GitHub Release (with the `.vsix`) on a `vscode-v*` tag.
