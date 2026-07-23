// Port of antares_cli/knowledge/cwe_database.py — loads the bundled MITRE CWE catalog.

import * as fs from "fs";
import * as path from "path";

export interface RelatedWeakness {
  nature: string;
  cwe_id: string;
  view_id: string;
  ordinal: string;
}

export interface ApplicablePlatform {
  type: string;
  class: string;
  name: string;
  prevalence: string;
}

export interface TaxonomyMapping {
  taxonomy_name: string;
  entry_id: string;
  entry_name: string;
  mapping_fit: string;
}

// Mirrors the 19-field CweEntry dataclass exactly (field names match the JSON).
export interface CweEntry {
  id: string;
  name: string;
  description: string;
  extended_description: string;
  detection_methods: string[];
  potential_mitigations: string[];
  abstraction: string;
  structure: string;
  status: string;
  likelihood_of_exploit: string;
  related_weaknesses: RelatedWeakness[];
  applicable_platforms: ApplicablePlatform[];
  modes_of_introduction: string[];
  common_consequences: string[];
  taxonomy_mappings: TaxonomyMapping[];
  mapping_usage: string;
  mapping_rationale: string;
  view_ids: string[];
  view_names: string[];
}

export interface CweTaxonomyMetadata {
  catalog: string;
  version: string;
  release_date: string;
  source_url: string;
  archive_sha256: string;
  entry_count: number;
}

function cweSortKey(entry: CweEntry): [number, string] {
  const parts = entry.id.split("-");
  if (parts.length >= 2) {
    const numeric = Number.parseInt(parts[1], 10);
    if (Number.isFinite(numeric)) {
      return [numeric, entry.id];
    }
  }
  return [10_000, entry.id];
}

export class CweDatabase {
  private readonly entries: CweEntry[];
  private readonly entriesById: Map<string, CweEntry>;
  readonly metadata: CweTaxonomyMetadata | undefined;

  constructor(entries: CweEntry[], metadata?: CweTaxonomyMetadata) {
    this.entries = [...entries].sort((a, b) => {
      const [an, aid] = cweSortKey(a);
      const [bn, bid] = cweSortKey(b);
      return an !== bn ? an - bn : aid < bid ? -1 : aid > bid ? 1 : 0;
    });
    this.entriesById = new Map(this.entries.map((entry) => [entry.id.toUpperCase(), entry]));
    this.metadata = metadata;
    if (metadata !== undefined && metadata.entry_count !== entries.length) {
      throw new Error(
        `CWE metadata declares ${metadata.entry_count} entries, loaded ${entries.length}`
      );
    }
  }

  // Load the catalog from a directory containing cwe_database.json / cwe_metadata.json.
  static loadDefault(dataDir: string): CweDatabase {
    const dbPath = path.join(dataDir, "cwe_database.json");
    const rawEntries = JSON.parse(fs.readFileSync(dbPath, "utf-8")) as CweEntry[];
    const metadataPath = path.join(dataDir, "cwe_metadata.json");
    let metadata: CweTaxonomyMetadata | undefined;
    if (fs.existsSync(metadataPath)) {
      metadata = JSON.parse(fs.readFileSync(metadataPath, "utf-8")) as CweTaxonomyMetadata;
    }
    return new CweDatabase(rawEntries, metadata);
  }

  getById(cweId: string): CweEntry | undefined {
    let normalized = cweId.toUpperCase().trim();
    if (!normalized.startsWith("CWE-")) {
      normalized = `CWE-${normalized}`;
    }
    return this.entriesById.get(normalized);
  }

  listAll(): CweEntry[] {
    return [...this.entries];
  }
}
