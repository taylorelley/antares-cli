# Antares Security Scanner — Walkthrough

## Step 1: Install

Antares is already installed. If you see this walkthrough, the extension is active.

## Step 2: Configure Endpoint

Antares connects to an inference endpoint (Ollama, OpenAI-compatible, or vLLM).

1. Open **Settings** (`Ctrl+,` / `Cmd+,`)
2. Search for `antares`
3. Set the **Provider** (default: `ollama`)
4. Set the **Endpoint** (default: `http://localhost:11434/v1`)
5. Set the **Model** to the model ID your endpoint serves (e.g. `qwen2.5-coder:7b`, `antares-1b`)

> **Tip**: If you use Ollama, ensure it is running and the model is pulled.

[Open Settings](command:workbench.action.openSettings?%22antares%22)

## Step 3: Test Connection

Once configured, test that Antares can reach your endpoint:

[Test Connection](command:antares.testConnection)

A notification will show whether the connection succeeded and which model is available.

## Step 4: First Scan

You can now run your first scan:

- **[Scan Folder for CWE…](command:antares.scanForCwe)** — Enter specific CWE IDs to scan for
- **[Auto-Sweep Folder](command:antares.autoSweep)** — Let Antares select CWE classes automatically
- **[Run SAST Scan (Opengrep)](command:antares.sastScan)** — Quick static analysis with Opengrep
- **[Run SAST + Verify](command:antares.sastScanAndVerify)** — SAST scan followed by AI verification

Results appear in the **Antares** view and the **Problems** panel.

### Viewing Reports

- **[Open Report Webview](command:antares.showReport)** — Rich interactive report with filtering, sorting, and triage
- **[Show History](command:antares.showHistory)** — Browse previous scan results

### Need Help?

- Check the **Antares** output channel for detailed logs
- Report issues on [GitHub](https://github.com/taylorelley/antares-cli)
