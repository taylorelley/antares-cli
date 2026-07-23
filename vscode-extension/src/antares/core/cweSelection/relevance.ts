// Port of antares_cli/core/cwe_selection_relevance.py — repository relevance checks.

import { CweEntry } from "../../knowledge/cweDatabase";
import { RepositoryProfile, ScanScope } from "./models";

const CURRENT_TOP_25_VIEW_ID = "CWE-1435";
const CURRENT_OWASP_VIEW_ID = "CWE-1450";

const BROAD_LANGUAGE_CLASSES = new Set([
  "Compiled", "Interpreted", "Memory-Unsafe", "Not Language-Specific", "Object-Oriented",
]);
const BROAD_LANGUAGE_NAMES = new Set(["", "Language-Independent", "Not Language-Specific", "SQL", "Unknown"]);
const UNRESTRICTED_LANGUAGE_CLASSES = new Set(["Not Language-Specific"]);
const UNRESTRICTED_LANGUAGE_NAMES = new Set(["Language-Independent", "Not Language-Specific", "Unknown"]);
const BROAD_TECHNOLOGY_CLASSES = new Set(["", "Not Technology-Specific"]);
const BROAD_TECHNOLOGY_NAMES = new Set(["", "Not Technology-Specific"]);
const LANGUAGE_NAME_TO_PROFILE: Record<string, string> = {
  "ASP.NET": "csharp", C: "c", "C#": "csharp", "C++": "cpp", Go: "go", Java: "java",
  JavaScript: "javascript", Perl: "perl", PHP: "php", Python: "python", Ruby: "ruby",
  Shell: "shell", Swift: "swift", TypeScript: "typescript", Verilog: "verilog",
  VHDL: "vhdl", XML: "xml",
};
const LANGUAGE_CLASS_TO_PROFILES: Record<string, Set<string>> = {
  Compiled: new Set(["c", "cpp", "csharp", "go", "java", "rust", "swift", "verilog", "vhdl"]),
  "Hardware Description Language": new Set(["verilog", "vhdl"]),
  Interpreted: new Set(["javascript", "perl", "php", "python", "ruby", "shell", "typescript"]),
  "Memory-Unsafe": new Set(["c", "cpp"]),
  "Object-Oriented": new Set(["cpp", "csharp", "java", "javascript", "php", "python", "ruby", "swift", "typescript"]),
};
const WEB_PROFILE_HINTS = new Set(["django", "express", "fastapi", "flask", "next", "rails", "react", "spring"]);
const MOBILE_PROFILE_HINTS = new Set(["android", "ios", "mobile", "react-native", "swift"]);
const AI_PROFILE_HINTS = new Set(["keras", "pytorch", "scikit-learn", "sklearn", "tensorflow", "torch"]);
const HARDWARE_PROFILE_LANGUAGES = new Set(["verilog", "vhdl"]);

function intersects<T>(a: Iterable<T>, b: Set<T>): boolean {
  for (const x of a) {
    if (b.has(x)) {
      return true;
    }
  }
  return false;
}

export function exclusionReason(entry: CweEntry, scope: ScanScope): string | null {
  if (entry.status === "Deprecated") {
    return "Excluded because MITRE marks this CWE as Deprecated";
  }
  if (scope === "top25" && !entry.view_ids.includes(CURRENT_TOP_25_VIEW_ID)) {
    return "Excluded because top25 mode only scans the current MITRE CWE Top 25";
  }
  if (scope === "owasp" && !entry.view_ids.includes(CURRENT_OWASP_VIEW_ID)) {
    return "Excluded because owasp mode only scans the current MITRE OWASP Top Ten view";
  }
  return null;
}

export function hasExactPlatformMatch(entry: CweEntry, profile: RepositoryProfile): boolean {
  const profileLanguages = new Set(Object.keys(profile.languages));
  return (
    intersects(concreteEntryLanguages(entry), profileLanguages) ||
    (entryHasWebPlatform(entry) && hasWebEvidence(profile)) ||
    (entryHasMobilePlatform(entry) && hasMobileEvidence(profile)) ||
    (entryHasAiPlatform(entry) && hasAiEvidence(profile)) ||
    (entryHasHardwarePlatform(entry) && hasHardwareEvidence(profile)) ||
    (hasCloudPlatform(entry) && (profile.iacSignals.length > 0 || profile.frameworks.includes("cloud")))
  );
}

export function hasConcreteLanguageMismatch(entry: CweEntry, profile: RepositoryProfile): boolean {
  const expected = concreteEntryLanguages(entry);
  if (
    expected.size === 0 ||
    hasUnrestrictedLanguageApplicability(entry) ||
    languageClassesMatchProfile(entry, profile) ||
    Object.keys(profile.languages).length === 0
  ) {
    return false;
  }
  return !intersects(Object.keys(profile.languages), expected);
}

function concreteEntryLanguages(entry: CweEntry): Set<string> {
  const concrete = new Set<string>();
  for (const platform of entry.applicable_platforms) {
    if (platform.type !== "Language") {
      continue;
    }
    if (BROAD_LANGUAGE_CLASSES.has(platform.class ?? "") || BROAD_LANGUAGE_NAMES.has(platform.name ?? "")) {
      continue;
    }
    const mapped = LANGUAGE_NAME_TO_PROFILE[platform.name ?? ""];
    if (mapped !== undefined) {
      concrete.add(mapped);
    }
  }
  return concrete;
}

function hasUnrestrictedLanguageApplicability(entry: CweEntry): boolean {
  return entry.applicable_platforms.some(
    (p) =>
      p.type === "Language" &&
      (UNRESTRICTED_LANGUAGE_CLASSES.has(p.class ?? "") || UNRESTRICTED_LANGUAGE_NAMES.has(p.name ?? ""))
  );
}

function languageClassesMatchProfile(entry: CweEntry, profile: RepositoryProfile): boolean {
  const profileLanguages = new Set(Object.keys(profile.languages));
  return entry.applicable_platforms.some(
    (p) => p.type === "Language" && intersects(profileLanguages, LANGUAGE_CLASS_TO_PROFILES[p.class ?? ""] ?? new Set())
  );
}

function concreteTechnologies(entry: CweEntry): { class?: string; name?: string }[] {
  return entry.applicable_platforms.filter((p) => {
    if (p.type !== "Technology") {
      return false;
    }
    return !(BROAD_TECHNOLOGY_CLASSES.has(p.class ?? "") && BROAD_TECHNOLOGY_NAMES.has(p.name ?? ""));
  });
}

function platformValues(platform: { class?: string; name?: string }): Set<string> {
  return new Set([platform.class ?? "", platform.name ?? ""]);
}

function entryHasWebPlatform(entry: CweEntry): boolean {
  return concreteTechnologies(entry).some((p) =>
    intersects(["Web Based", "Web Server", "Browser"], platformValues(p))
  );
}
function entryHasMobilePlatform(entry: CweEntry): boolean {
  return concreteTechnologies(entry).some((p) => platformValues(p).has("Mobile"));
}
function entryHasAiPlatform(entry: CweEntry): boolean {
  return concreteTechnologies(entry).some((p) => intersects(["AI/ML", "Machine Learning"], platformValues(p)));
}
function entryHasHardwarePlatform(entry: CweEntry): boolean {
  const markers = [
    "Bus/Interface", "Hardware", "ICS/OT", "Memory Hardware", "Microcontroller Hardware",
    "Power Management", "Processor Hardware", "Security Hardware", "Sensor", "System on Chip",
  ];
  return concreteTechnologies(entry).some((p) =>
    [...platformValues(p)].some((value) => markers.some((m) => value.includes(m)))
  );
}
function hasCloudPlatform(entry: CweEntry): boolean {
  return concreteTechnologies(entry).some(
    (p) => (p.class ?? "").includes("Cloud") || (p.name ?? "").includes("Cloud")
  );
}

function hasWebEvidence(profile: RepositoryProfile): boolean {
  return (
    intersects(profile.frameworks, WEB_PROFILE_HINTS) ||
    profile.routeFiles.length > 0 ||
    profile.requestInputSignals.length > 0 ||
    profile.templateSignals.length > 0 ||
    profile.uploadSignals.length > 0
  );
}
function hasHardwareEvidence(profile: RepositoryProfile): boolean {
  return intersects(Object.keys(profile.languages), HARDWARE_PROFILE_LANGUAGES);
}
function hasMobileEvidence(profile: RepositoryProfile): boolean {
  return intersects(profile.frameworks, MOBILE_PROFILE_HINTS) || "swift" in profile.languages;
}
function hasAiEvidence(profile: RepositoryProfile): boolean {
  return intersects(profile.frameworks, AI_PROFILE_HINTS);
}
