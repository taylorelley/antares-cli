// Port of antares_cli/agent/streaming.py — streaming parser for Antares tool-call markup.

const UNCLOSED_TOOL_CALL_PATTERN = /<tool_call>\s*(\{[\s\S]*)/;
const FRAMING_TOKENS = ["<|end_of_text|>", "<|endoftext|>", "<|eot_id|>", "<think>", "</think>"];
const EOS_TOKENS = /<\|end_of_text\|>|<\|endoftext\|>|<\|eot_id\|>/g;
const THINK_TAGS = /<\/?think>/g;
const WRAPPED_OPEN_TAGS: Record<string, string> = {
  tool_call: "<tool_call>",
  done: "<done>",
  answer: "<answer>",
};
const MAX_RECOVERY_CANDIDATES = 256;
const MAX_RECOVERY_TEXT_LENGTH = 131_072;

export interface ParsedTextChunk {
  kind: "text";
  text: string;
}
export interface ParsedToolCall {
  kind: "tool_call";
  toolName: string;
  arguments: Record<string, unknown>;
}
export interface ParsedDoneSignal {
  kind: "done";
}
export interface ParsedAnswer {
  kind: "answer";
  text: string;
}
export type ParsedEvent = ParsedTextChunk | ParsedToolCall | ParsedDoneSignal | ParsedAnswer;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSpace(character: string): boolean {
  return /\s/.test(character);
}

// Equivalent of json.JSONDecoder().raw_decode over a string starting with '{':
// returns [object, endIndex] or throws when the object is incomplete/invalid.
function rawDecodeObject(text: string): [unknown, number] {
  const end = balancedJsonObjectEnd(text);
  if (end === null) {
    throw new Error("incomplete JSON object");
  }
  const value = JSON.parse(text.slice(0, end));
  return [value, end];
}

function lenientJsonLoads(raw: string): Record<string, unknown> | null {
  let text = raw.trim();
  try {
    const result = JSON.parse(text);
    if (isObject(result)) {
      return result;
    }
  } catch {
    // fall through
  }
  try {
    const [result] = rawDecodeObject(text);
    if (isObject(result)) {
      return result;
    }
  } catch {
    // fall through
  }
  for (let i = 0; i < 3; i++) {
    if (!text.endsWith("}")) {
      break;
    }
    text = text.slice(0, -1).replace(/\s+$/, "");
    try {
      const result = JSON.parse(text);
      if (isObject(result)) {
        return result;
      }
    } catch {
      continue;
    }
  }
  return null;
}

function toolCallArguments(payload: Record<string, unknown>): unknown {
  if ("args" in payload) {
    return payload.args;
  }
  if ("arguments" in payload) {
    return payload.arguments;
  }
  const toolName = payload.tool ?? payload.name;
  if (toolName === "submit_no_vulnerability_found") {
    return {};
  }
  return null;
}

function isToolCallPayload(payload: unknown): payload is Record<string, unknown> {
  if (!isObject(payload)) {
    return false;
  }
  const toolName = payload.tool ?? payload.name;
  const argumentsValue = toolCallArguments(payload);
  return typeof toolName === "string" && isObject(argumentsValue);
}

function buildToolCall(payload: Record<string, unknown>): ParsedEvent {
  const toolName = payload.tool ?? payload.name;
  const argumentsValue = toolCallArguments(payload);
  if (typeof toolName !== "string") {
    return { kind: "text", text: "parse error: tool_call missing 'tool'/'name' (str)" };
  }
  if (!isObject(argumentsValue)) {
    return { kind: "text", text: "parse error: tool_call missing 'args'/'arguments' (dict)" };
  }
  const normalized = toolName.trim().toLowerCase().replace(/[\s-]+/g, "_");
  return { kind: "tool_call", toolName: normalized, arguments: argumentsValue };
}

function buildWrappedPayload(tagName: string, payload: unknown): ParsedEvent {
  if (!isObject(payload)) {
    return { kind: "text", text: `parse error: invalid JSON object in <${tagName}>` };
  }
  if (tagName === "tool_call") {
    return buildToolCall(payload);
  }
  return { kind: "done" };
}

function appendPlainText(events: ParsedEvent[], text: string): void {
  const cleaned = text.replace(EOS_TOKENS, "").replace(THINK_TAGS, "");
  if (cleaned) {
    events.push({ kind: "text", text: cleaned });
  }
}

function nextWrappedOpenTag(text: string): [string, number] | null {
  let best: [string, number] | null = null;
  for (const [tagName, openingTag] of Object.entries(WRAPPED_OPEN_TAGS)) {
    const position = text.indexOf(openingTag);
    if (position >= 0 && (best === null || position < best[1])) {
      best = [tagName, position];
    }
  }
  return best;
}

function nextRawObjectStart(text: string): number | null {
  let searchStart = 0;
  let candidateStart: number;
  while ((candidateStart = text.indexOf("{", searchStart)) >= 0) {
    let index = candidateStart + 1;
    while (index < text.length && isSpace(text[index])) {
      index += 1;
    }
    if (index === text.length || text[index] === '"' || text[index] === "}") {
      return candidateStart;
    }
    searchStart = candidateStart + 1;
  }
  return null;
}

function rawObjectPrefixIsInvalid(text: string): boolean {
  let index = 1;
  while (index < text.length && isSpace(text[index])) {
    index += 1;
  }
  return index < text.length && text[index] !== '"' && text[index] !== "}";
}

function balancedJsonObjectEnd(text: string): number | null {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
      continue;
    }
    if (character === '"') {
      inString = true;
    } else if (character === "{") {
      depth += 1;
    } else if (character === "}") {
      depth -= 1;
      if (depth === 0) {
        return index + 1;
      }
    }
  }
  return null;
}

function allSubstringPositions(text: string, needle: string): number[] {
  const positions: number[] = [];
  let searchStart = 0;
  let position: number;
  while ((position = text.indexOf(needle, searchStart)) >= 0) {
    positions.push(position);
    searchStart = position + 1;
  }
  return positions;
}

function allRawObjectStarts(text: string): number[] {
  const starts: number[] = [];
  let searchStart = 0;
  while (searchStart < text.length) {
    const relativeStart = nextRawObjectStart(text.slice(searchStart));
    if (relativeStart === null) {
      break;
    }
    const absoluteStart = searchStart + relativeStart;
    starts.push(absoluteStart);
    searchStart = absoluteStart + 1;
  }
  return starts;
}

function recoverStructuredSuffix(text: string): [number, ParsedEvent[]] | null {
  const recoveryOffset = Math.max(0, text.length - MAX_RECOVERY_TEXT_LENGTH);
  const recoveryText = text.slice(recoveryOffset);
  const candidateStarts = new Set<number>();
  for (const openingTag of Object.values(WRAPPED_OPEN_TAGS)) {
    for (const position of allSubstringPositions(recoveryText, openingTag)) {
      if (position > 0) {
        candidateStarts.add(position);
      }
    }
  }
  for (const position of allRawObjectStarts(recoveryText)) {
    if (position > 0) {
      candidateStarts.add(position);
    }
  }
  const ordered = [...candidateStarts].sort((a, b) => a - b).slice(-MAX_RECOVERY_CANDIDATES);
  for (const candidateStart of ordered) {
    const parser = new StreamingToolCallParser(false);
    const recoveredEvents = parser.feed(recoveryText.slice(candidateStart));
    recoveredEvents.push(...parser.flush());
    if (recoveredEvents.some((event) => event.kind !== "text")) {
      return [recoveryOffset + candidateStart, recoveredEvents];
    }
  }
  return null;
}

function safePlainTextCutoff(text: string, requestedCutoff: number): number {
  const maxTokenLen = Math.max(...FRAMING_TOKENS.map((t) => t.length));
  const earliestStart = Math.max(0, requestedCutoff - maxTokenLen + 1);
  for (let tokenStart = earliestStart; tokenStart < requestedCutoff; tokenStart++) {
    for (const token of FRAMING_TOKENS) {
      if (
        tokenStart < requestedCutoff &&
        requestedCutoff < tokenStart + token.length &&
        text.startsWith(token, tokenStart)
      ) {
        return tokenStart;
      }
    }
  }
  return requestedCutoff;
}

export class StreamingToolCallParser {
  private buffer = "";
  private rawCandidateActive = false;
  private rawDecodeMayComplete = false;
  private readonly recoverStructuredSuffixEnabled: boolean;

  constructor(recoverStructuredSuffix = true) {
    this.recoverStructuredSuffixEnabled = recoverStructuredSuffix;
  }

  feed(textChunk: string): ParsedEvent[] {
    this.buffer += textChunk;
    if (this.rawCandidateActive && textChunk.includes("}")) {
      this.rawDecodeMayComplete = true;
    }
    const events: ParsedEvent[] = [];
    while (this.consumeNextEvent(events)) {
      // keep consuming
    }
    this.emitStreamablePlainText(events);
    return events;
  }

  flush(): ParsedEvent[] {
    const events: ParsedEvent[] = [];
    while (this.consumeNextEvent(events)) {
      // keep consuming
    }
    if (!this.buffer) {
      return events;
    }
    const remainingText = this.buffer;
    this.buffer = "";
    this.rawCandidateActive = false;
    this.rawDecodeMayComplete = false;
    const recovered = this.recoverStructuredSuffixEnabled
      ? recoverStructuredSuffix(remainingText)
      : null;
    if (recovered !== null) {
      const [recoveryStart, recoveredEvents] = recovered;
      appendPlainText(events, remainingText.slice(0, recoveryStart));
      events.push(...recoveredEvents);
      return events;
    }
    const unclosedMatch = UNCLOSED_TOOL_CALL_PATTERN.exec(remainingText);
    if (unclosedMatch) {
      const payload = lenientJsonLoads(unclosedMatch[1]);
      if (payload !== null && isToolCallPayload(payload)) {
        appendPlainText(events, remainingText.slice(0, unclosedMatch.index));
        events.push(buildToolCall(payload));
        return events;
      }
    }
    appendPlainText(events, remainingText);
    return events;
  }

  private consumeNextEvent(events: ParsedEvent[]): boolean {
    const wrappedTag = nextWrappedOpenTag(this.buffer);
    const rawStart = nextRawObjectStart(this.buffer);
    if (rawStart !== null && (wrappedTag === null || rawStart < wrappedTag[1])) {
      return this.consumeRawObject(events, rawStart);
    }
    if (wrappedTag !== null) {
      return this.consumeWrappedEvent(events, wrappedTag[0], wrappedTag[1]);
    }
    return false;
  }

  private consumeRawObject(events: ParsedEvent[], objectStart: number): boolean {
    if (objectStart > 0) {
      appendPlainText(events, this.buffer.slice(0, objectStart));
      this.buffer = this.buffer.slice(objectStart);
      this.rawCandidateActive = true;
      this.rawDecodeMayComplete = this.buffer.includes("}");
      return true;
    }

    if (!this.rawCandidateActive) {
      this.rawCandidateActive = true;
      this.rawDecodeMayComplete = this.buffer.includes("}");
    }
    if (rawObjectPrefixIsInvalid(this.buffer)) {
      appendPlainText(events, this.buffer[0]);
      this.buffer = this.buffer.slice(1);
      this.rawCandidateActive = false;
      this.rawDecodeMayComplete = false;
      return true;
    }
    if (!this.rawDecodeMayComplete) {
      return false;
    }
    this.rawDecodeMayComplete = false;

    let payload: unknown;
    let objectEnd: number;
    try {
      [payload, objectEnd] = rawDecodeObject(this.buffer);
    } catch {
      const completeEnd = balancedJsonObjectEnd(this.buffer);
      if (completeEnd !== null) {
        appendPlainText(events, this.buffer.slice(0, completeEnd));
        this.buffer = this.buffer.slice(completeEnd);
        this.rawCandidateActive = false;
        return true;
      }
      return false;
    }

    if (isToolCallPayload(payload)) {
      events.push(buildToolCall(payload));
    } else {
      appendPlainText(events, this.buffer.slice(0, objectEnd));
    }
    this.buffer = this.buffer.slice(objectEnd);
    this.rawCandidateActive = false;
    return true;
  }

  private consumeWrappedEvent(events: ParsedEvent[], tagName: string, tagStart: number): boolean {
    if (tagStart > 0) {
      appendPlainText(events, this.buffer.slice(0, tagStart));
      this.buffer = this.buffer.slice(tagStart);
      return true;
    }

    const openingTag = WRAPPED_OPEN_TAGS[tagName];
    const contentStart = openingTag.length;
    const closingTag = `</${tagName}>`;
    if (tagName === "answer") {
      const closingStart = this.buffer.indexOf(closingTag, contentStart);
      if (closingStart < 0) {
        return false;
      }
      const answerText = this.buffer.slice(contentStart, closingStart).trim();
      events.push({ kind: "answer", text: answerText });
      this.buffer = this.buffer.slice(closingStart + closingTag.length);
      return true;
    }

    let jsonStart = contentStart;
    while (jsonStart < this.buffer.length && isSpace(this.buffer[jsonStart])) {
      jsonStart += 1;
    }
    if (jsonStart >= this.buffer.length) {
      return false;
    }

    let payload: unknown;
    let relativeEnd: number;
    try {
      [payload, relativeEnd] = rawDecodeObject(this.buffer.slice(jsonStart));
    } catch {
      return this.consumeInvalidOrLenientWrappedEvent(events, tagName, contentStart, closingTag);
    }

    const jsonEnd = jsonStart + relativeEnd;
    let closingStart = jsonEnd;
    while (closingStart < this.buffer.length && isSpace(this.buffer[closingStart])) {
      closingStart += 1;
    }
    if (this.buffer.startsWith(closingTag, closingStart)) {
      events.push(buildWrappedPayload(tagName, payload));
      this.buffer = this.buffer.slice(closingStart + closingTag.length);
      return true;
    }

    const laterClosingStart = this.buffer.indexOf(closingTag, jsonEnd);
    if (laterClosingStart < 0) {
      return false;
    }
    return this.consumeLenientWrappedPayload(events, tagName, contentStart, laterClosingStart, closingTag);
  }

  private consumeInvalidOrLenientWrappedEvent(
    events: ParsedEvent[],
    tagName: string,
    contentStart: number,
    closingTag: string
  ): boolean {
    const closingStart = this.buffer.indexOf(closingTag, contentStart);
    if (closingStart < 0) {
      return false;
    }
    return this.consumeLenientWrappedPayload(events, tagName, contentStart, closingStart, closingTag);
  }

  private consumeLenientWrappedPayload(
    events: ParsedEvent[],
    tagName: string,
    contentStart: number,
    closingStart: number,
    closingTag: string
  ): boolean {
    const payload = lenientJsonLoads(this.buffer.slice(contentStart, closingStart));
    if (payload === null) {
      events.push({ kind: "text", text: `parse error: invalid JSON in <${tagName}>` });
    } else {
      events.push(buildWrappedPayload(tagName, payload));
    }
    this.buffer = this.buffer.slice(closingStart + closingTag.length);
    return true;
  }

  private emitStreamablePlainText(events: ParsedEvent[]): void {
    if (this.rawCandidateActive || nextWrappedOpenTag(this.buffer) !== null) {
      return;
    }
    if (nextRawObjectStart(this.buffer) !== null || this.buffer.length <= 512) {
      return;
    }
    const safeCutoff = safePlainTextCutoff(this.buffer, this.buffer.length - 256);
    if (safeCutoff === 0) {
      return;
    }
    const safeText = this.buffer.slice(0, safeCutoff);
    this.buffer = this.buffer.slice(safeCutoff);
    appendPlainText(events, safeText);
  }
}

// Clean model text of EOS + think tags (used by the adapter). Mirrors _append_plain_text.
export function stripFramingTokens(text: string): string {
  return text.replace(EOS_TOKENS, "").replace(THINK_TAGS, "");
}
