// Port of antares_cli/core/cwe_selection_evidence.py — generic CWE evidence matcher.

import { EvidenceRuleData } from "./tables";

export interface CweEvidenceMatch {
  cweId: string;
  label: string;
  score: number;
}

export function detectCweEvidence(
  lowerText: string,
  language: string,
  rules: EvidenceRuleData[]
): CweEvidenceMatch[] {
  const matches: CweEvidenceMatch[] = [];
  for (const rule of rules) {
    if (rule.languages.length > 0 && !rule.languages.includes(language)) {
      continue;
    }
    if (!rule.tokens.some((token) => lowerText.includes(token))) {
      continue;
    }
    const requiredGroupsSatisfied = rule.required_token_groups.every((group) =>
      group.some((token) => lowerText.includes(token))
    );
    if (!requiredGroupsSatisfied) {
      continue;
    }
    for (const [cweId, score] of rule.cwe_scores) {
      matches.push({ cweId, label: rule.label, score });
    }
  }
  return matches;
}
