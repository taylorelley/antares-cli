# Antares Security Scanner for VS Code

Run the [Antares](../README.md) CWE vulnerability-localization agent directly from VS
Code. Antares reads your code (read-only) and reports a ranked list of files that likely
contain a given class of vulnerability (CWE), surfaced in the **Problems panel** and a
dedicated **Antares** view.

The model is fully configurable and works against **OpenAI-API-compatible** servers and
**Ollama** — including a local Ollama instance out of the box.

## How it works

The extension does not reimplement Antares. It spawns a small Python host
(`python/antares_host.py`) that imports the Antares `SecurityWorkflowService` and streams
results back over JSON. On first use the extension provisions a **managed virtual
environment** and installs `antares-cli` into it, so there is nothing to install by hand.

```
VS Code extension  ──spawn──▶  python/antares_host.py  ──imports──▶  antares_cli service
      ▲                                   │
      └────────── NDJSON events ──────────┘   (progress, findings, final result)
```

## Requirements

- **Python 3.11+** available on your machine (used to create the managed environment).
  If you already have `antares-cli` installed in an interpreter, point `antares.pythonPath`
  at it and it is used directly — no environment is created.
- Access to an inference endpoint:
  - **Ollama**: run `ollama serve` and pull a model (e.g. `ollama pull qwen2.5-coder`).
  - **OpenAI-compatible** server (vLLM, LM Studio, a gateway, etc.).
  - **vLLM-hosted Antares checkpoints** for the tested `/v1/completions` path.

## Quick start (Ollama)

1. Install and start Ollama, then pull a code model:
   `ollama pull qwen2.5-coder`.
2. In VS Code settings, set **Antares: Model** to the model id (e.g. `qwen2.5-coder`).
   The default provider is **Ollama** and the endpoint defaults to
   `http://localhost:11434/v1`.
3. Run **Antares: Auto-Sweep Folder for Vulnerabilities** from the Command Palette, or
   right-click a folder in the Explorer → **Antares: Scan Folder for CWE…**.
4. Findings appear in the **Problems panel** and the **Antares** activity-bar view.

## Commands

| Command | Description |
| --- | --- |
| `Antares: Scan Folder for CWE…` | Prompts for CWE IDs and scans a folder for exactly those classes. |
| `Antares: Auto-Sweep Folder for Vulnerabilities` | Lets Antares auto-select likely CWE classes and scans in parallel. |
| `Antares: Set API Key` | Stores an API key in VS Code SecretStorage (passed to the endpoint as a bearer token). |
| `Antares: Clear API Key` | Removes the stored API key. |
| `Antares: Set Up Python Environment` | Provisions the managed virtual environment ahead of time. |
| `Antares: Show Last Report (JSON)` | Opens the most recent result as JSON. |
| `Antares: Clear Results` | Clears diagnostics and the results view. |

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `antares.provider` | `ollama` | Connection preset: `ollama`, `openai-compatible`, `vllm`, or `custom`. |
| `antares.endpoint` | `""` | Inference base URL. Empty uses the provider default (Ollama only). |
| `antares.model` | `""` | Served model id — must match the endpoint exactly. |
| `antares.apiStyle` | `auto` | `auto`, `chat` (`/v1/chat/completions`), or `completions` (`/v1/completions`). |
| `antares.pythonPath` | `""` | Interpreter to use / base for the managed venv. Auto-detected when empty. |
| `antares.autoInstall` | `true` | Create the managed venv and install `antares-cli` automatically. |
| `antares.packageSpec` | `antares-cli` | pip requirement for the install (version pin, local path, or wheel). |
| `antares.toolBudget` | `0` | Tool-call budget per scan (`0` = Antares default). |
| `antares.sweep.workers` | `4` | Parallel CWE workers for Auto-Sweep. |
| `antares.sweep.maxCwes` | `8` | Max CWE classes Auto-Sweep selects. |
| `antares.diagnosticsSeverity` | `warning` | Severity used for findings in the Problems panel. |

### API style and providers

Antares talks to two OpenAI-compatible shapes:

- **`chat`** → `POST /v1/chat/completions` — used by **Ollama** and most OpenAI-compatible
  servers. This is the default for the `ollama` and `openai-compatible` presets.
- **`completions`** → `POST /v1/completions` — the tested path for **vLLM-hosted Antares
  checkpoints** (applies the Granite template locally). Default for the `vllm` preset.

When `antares.apiStyle` is `auto`, the style is derived from the provider. Set it
explicitly to override.

### API key

For keyless servers such as a local Ollama, no key is needed. For hosted endpoints, run
**Antares: Set API Key**; the key is stored in VS Code SecretStorage and passed to the
Python host through the `ANTARES_API_KEY` environment variable — it is never written to
settings or the command line.

## Development

```bash
npm install
npm run compile        # bundle to dist/extension.js (esbuild)
npm run check-types    # tsc --noEmit
npm run test-unit      # node --test for the pure request-building logic
```

Press **F5** in VS Code to launch an Extension Development Host.

The bundled `python/antares_host.py` speaks newline-delimited JSON: a single request
object on stdin, then `ready` / `progress` / `worker` / `finding` / `result` / `error`
event objects on stdout. See the file header for the full protocol.
