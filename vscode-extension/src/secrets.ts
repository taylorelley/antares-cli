import * as vscode from "vscode";

const API_KEY_SECRET = "antares.apiKey";

export async function getApiKey(context: vscode.ExtensionContext): Promise<string | undefined> {
  return context.secrets.get(API_KEY_SECRET);
}

export async function promptAndStoreApiKey(
  context: vscode.ExtensionContext
): Promise<boolean> {
  const value = await vscode.window.showInputBox({
    title: "Antares API Key",
    prompt: "Enter the API key for your inference endpoint (leave empty for keyless servers like Ollama).",
    password: true,
    ignoreFocusOut: true,
  });
  if (value === undefined) {
    return false;
  }
  if (value.trim() === "") {
    await context.secrets.delete(API_KEY_SECRET);
    void vscode.window.showInformationMessage("Antares API key cleared.");
    return true;
  }
  await context.secrets.store(API_KEY_SECRET, value.trim());
  void vscode.window.showInformationMessage("Antares API key stored securely.");
  return true;
}

export async function clearApiKey(context: vscode.ExtensionContext): Promise<void> {
  await context.secrets.delete(API_KEY_SECRET);
  void vscode.window.showInformationMessage("Antares API key cleared.");
}
