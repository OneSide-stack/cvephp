/**
 * Verified facts about CVE-2026-109618 (PHP2Shell).
 *
 * Every constant below was checked against a primary upstream source on
 * 2026-10-24; see docs/CVE-VERIFICATION.md for the retrieval and diff record.
 * The UI must present these as *verified advisory facts*, and keep them clearly
 * separate from what the running lab guest has actually demonstrated.
 */

export interface AdvisoryFact {
  id: string;
  advisory: string;
  advisoryUrl: string;
  title: string;
  published: string;
  packageName: string;
  affected: string[];
  patched: string[];
  companion: { cve: string; advisory: string };
  verifiedAt: string;
}

export const ADVISORY: AdvisoryFact = {
  id: "CVE-2026-109618",
  advisory: "GHSA-w8hw-w9fx-j79w",
  advisoryUrl: "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
  title: "RCE via OOM corruption",
  published: "2026-10-21",
  packageName: "php-src (PHP)",
  affected: ["< 8.2.35", "< 8.3.36", "< 8.4.27", "< 8.5.12"],
  patched: ["8.2.35", "8.3.36", "8.4.27", "8.5.12"],
  companion: { cve: "CVE-2026-109619", advisory: "GHSA-6wmf-4rv5-p3rp" },
  verifiedAt: "2026-10-24",
};

/** First patched release per maintenance branch, as published in the advisory. */
export const PATCHED_RELEASES: Record<string, number> = { "8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12 };

/**
 * The patch added this INI directive. Its presence is a build-level marker of
 * the fixed allocator (Zend/zend_alloc.c delayed OOM + main/main.c hard limit),
 * independent of any version banner.
 */
export const PATCH_INI_MARKER = "memory_hard_limit_percent";

/** Upstream source digests pinned by the repository, re-verified from codeload.github.com. */
export const PINNED_SOURCES = [
  {
    tag: "php-8.2.34",
    role: "vulnerable" as const,
    sha256: "97334269c64e2dfe167500c75846f981b0b93539297e8d03ae370e420c0d524e",
    url: "https://github.com/php/php-src/releases/tag/php-8.2.34",
  },
  {
    tag: "php-8.2.35",
    role: "patched" as const,
    sha256: "c191fd6f3daaa842b744b562b157badffb62d225cdb6405ca8b2c86d27c27438",
    url: "https://github.com/php/php-src/releases/tag/php-8.2.35",
  },
];

/** Mechanisms named by the advisory. Used for the configuration assessment text. */
export const OOM_STRATEGIES = [
  "A multipart request without a usable declared content length may pass the initial post_max_size check and continue supplying decoded body data.",
  "A multipart part can contain an unrestricted number of headers; their in-memory representation can cost far more than the wire bytes.",
  "Empty file controls do not count towards max_file_uploads but still create file metadata arrays.",
  "Nested field names multiply the generated array work.",
];

export const ADVISORY_GUIDANCE = [
  "Updating to a release containing the patch is the only complete mitigation.",
  "For installations that cannot update, enforce memory_limit=-1 administratively and restart every PHP worker.",
  "Keep post_max_size conservative and independently enforce the decoded request size at the frontend.",
  "Reduce max_input_nesting_level and bound input variables, multipart parts, part headers and uploads.",
  "If the application does not use multipart form data, block such requests before they reach PHP.",
];

/**
 * Reproduction status for the lab's own 32-bit Alpine/musl build. This is the
 * honest position: the advisory is verified, exploitation of this exact binary
 * is not. Only independent target-side evidence can change it.
 */
export const LAB_REPRODUCTION_STATEMENT =
  "The advisory and the patch are verified. Genuine exploitation of this 32-bit Alpine/musl mod_php build is not verified, so the lab never awards RCE completion from a version string, an OOM fatal, an HTTP status, or a simulated terminal.";

export function parsePhpVersion(version: string): { major: number; minor: number; patch: number } | null {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version.trim());
  if (!match) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

/**
 * Classify a build from *observed* guest facts.
 *
 * The classification deliberately uses two independent signals:
 *  - the running PHP version against the published fix table;
 *  - the presence of the patch's INI marker.
 * If they disagree the result is "unknown" with a conflict explanation, never a
 * guess in the learner's favour.
 */
export function classifyObservedBuild(input: {
  phpVersion: string;
  sapi: string;
  hardLimitDirective: string | null;
}): { classification: "vulnerable-build" | "patched-build" | "unknown"; basis: string } {
  const parsed = parsePhpVersion(input.phpVersion);
  if (!parsed) {
    return { classification: "unknown", basis: `The guest did not report a parsable PHP version (${JSON.stringify(input.phpVersion)}).` };
  }
  const fixed = PATCHED_RELEASES[`${parsed.major}.${parsed.minor}`];
  if (fixed === undefined) {
    return {
      classification: "unknown",
      basis: `PHP ${input.phpVersion} is outside the branches named by the advisory, so neither the fix table nor the patch marker can classify it.`,
    };
  }
  const versionPatched = parsed.patch >= fixed;
  const markerPresent = input.hardLimitDirective !== null && input.hardLimitDirective !== "";
  const versionText = `PHP ${input.phpVersion} is ${versionPatched ? "at or above" : "below"} the first fixed release ${parsed.major}.${parsed.minor}.${fixed}`;
  const markerText = `the ${PATCH_INI_MARKER} directive is ${markerPresent ? "present" : "absent"} in the running build`;

  if (versionPatched && markerPresent) {
    return { classification: "patched-build", basis: `${versionText}; ${markerText}. Both independent signals agree.` };
  }
  if (!versionPatched && !markerPresent) {
    return {
      classification: "vulnerable-build",
      basis: `${versionText}; ${markerText}. The build predates the allocator fix and the request-processing path named by the advisory is compiled in.`,
    };
  }
  return {
    classification: "unknown",
    basis: `Conflicting evidence: ${versionText}, but ${markerText}. A distribution backport or version mismatch cannot be resolved from these observations alone.`,
  };
}

export function isModPhp(sapi: string): boolean {
  return /apache2handler|apache2filter/i.test(sapi);
}
