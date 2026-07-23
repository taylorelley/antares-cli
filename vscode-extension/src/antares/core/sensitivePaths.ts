// Port of antares_cli/core/sensitive_paths.py — repository-local sensitive path policy.

const SENSITIVE_DIRECTORY_NAMES = new Set([
  ".aws",
  ".azure",
  ".docker",
  ".gnupg",
  ".kube",
  ".ssh",
  "gcloud",
]);

const SENSITIVE_FILE_NAMES = new Set([
  ".git-credentials",
  ".netrc",
  ".npmrc",
  ".pypirc",
  "application_default_credentials.json",
  "credentials",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "id_rsa",
  "key.json",
  "kubeconfig",
]);

const SENSITIVE_FILE_SUFFIXES = [".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"];

// Return whether a repository-relative path is protected by default.
export function isSensitiveRepositoryPath(relativePath: string): boolean {
  let normalized = relativePath.replace(/\\/g, "/").toLowerCase();
  while (normalized.startsWith("./")) {
    normalized = normalized.slice(2);
  }
  const parts = normalized.split("/").filter((part) => part.length > 0);
  const name = parts.length > 0 ? parts[parts.length - 1] : "";
  if (name.startsWith(".env")) {
    return true;
  }
  if (parts.some((part) => SENSITIVE_DIRECTORY_NAMES.has(part))) {
    return true;
  }
  if (SENSITIVE_FILE_NAMES.has(name) || SENSITIVE_FILE_SUFFIXES.some((s) => name.endsWith(s))) {
    return true;
  }
  return (
    name.endsWith(".json") &&
    (name.startsWith("service-account") || name.endsWith("-credentials.json"))
  );
}
