// Pragmatic port of antares_cli/agent/quarantine.py. The full Python version runs a
// pattern engine over model-visible content; here we implement the load-bearing
// defense — stripping control tags from tool OUTPUT so repository content cannot forge
// model-control turns — plus a safety hook for tool calls (path safety is already
// enforced by the sandbox policy layer, so this never blocks on its own).

const INJECTED_TAG_PATTERNS: [RegExp, string][] = [
  [/<tool_call\b[^>]*>(?!.*<\/tool_call>)/g, "[QUARANTINED: injected_tool_call_tag]"],
  [/<done>[\s\S]*?<\/done>/g, "[QUARANTINED: injected_done_tag]"],
  [/<answer>[\s\S]*?<\/answer>/g, "[QUARANTINED: injected_answer_tag]"],
  [/<finding>[\s\S]*?<\/finding>/g, "[QUARANTINED: injected_finding_tag]"],
];

export class ContentQuarantine {
  sanitize(text: string): string {
    let result = text;
    for (const [pattern, replacement] of INJECTED_TAG_PATTERNS) {
      result = result.replace(pattern, replacement);
    }
    return result;
  }
}

export interface ToolCallSafety {
  blocked: boolean;
  reason?: string;
}

export function validateToolCallSafety(
  _toolName: string,
  _args: Record<string, unknown>
): ToolCallSafety {
  return { blocked: false };
}
