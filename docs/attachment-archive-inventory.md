# Attachment ZIP metadata inventory

This audit corrects evidence accounting inside the existing attachment scanner.
It inventories ZIP central-directory declarations without reading/decompressing
members, rendering documents, executing content or performing network lookups.
The attachment payload, hashes and original email remain the evidence sources.

## Reproduced gaps

Actual `full --no-egress` cases on the merged baseline reproduced:

- A 1,001-entry ZIP reported a limit but retained no member records, and the
  attachment coverage stage still reported completed.
- A truncated ZIP reported an archive error but attachment coverage completed.
- A central-directory name containing NUL was shortened by `ZipInfo.filename`.
  Its lost suffix also escaped the unsafe-path check, which saw only the prefix.
- An unsupported ZIP reader version raised `NotImplementedError`. A message with
  three attachments retained one unlisted payload file, no `attachments.json`,
  and a failed attachment stage; the scanner stopped before the remaining parts.

The corrected reader keeps a bounded member prefix with explicit omissions,
preserves original parser names within name budgets and isolates supported reader
errors within each attachment. ZIP errors and inventory limits propagate to
attachment status `partial`; the existing stage aggregation consequently reports
partial while retaining the other attachments and their bytes.

## Field and budget contract

Existing ordinary member fields remain, with these additions:

- `entry_index`: zero-based central-directory parser order; duplicates remain
  separate records.
- `original_name`: untruncated `ZipInfo.orig_filename`, distinct from the existing
  normalized parser `name`. This is decoded text, not an original name byte span.
- `name_status`, `name_issues`, `name_utf8_bytes` and `name_normalized`: explicit
  captured/limited names, declared parser-name size and normalization.
- Inventory counts, omitted entry count, limited-name count, captured UTF-8 name
  bytes, issues, scope and `verified: false`.

Default limits retain at most 1,000 member records, 4,096 UTF-8 bytes per original
parser name and 262,144 captured original-name UTF-8 bytes per archive. A long or
over-budget name becomes null in both name views, with its issue and position
retained; size/encryption/path observations remain available. Later shorter names
can fit the remaining budget. Names reused by the macro-marker list are drawn
only from retained names; their bytes are charged once against the name budget.
The two name views and optional marker references may repeat the same text in
JSON; that output remains bounded by a fixed multiple of the name budget.

The existing 100 MiB declared expansion limit uses totals across all parser
entries, including omitted records; exceeding it reports a limit, not an actual
expansion attempt. A lower entry cap retains its prefix and full entry/declared
size counts. Invalid, noninteger, boolean or nonpositive limits are rejected.

Unsafe-path observations check the untruncated parser name, including NUL,
absolute paths, parent traversal and drive/colon components. They describe
declared path syntax, not an executed exploit or malware verdict. Member names
never become filesystem paths: attachment files still use generated part/hash
identities. `macro_container_entries` has explicit scope
`inventoried_entries_with_retained_parser_names`; missing markers beyond that
scope cannot establish absence of macros.

These are additional extraction bounds. The standard ZIP parser reads the
central directory before the retained-prefix/name limits apply. Existing MIME
input/decoded-byte limits and supervised worker memory/deadline limits still
bound analysis. This change does not introduce a custom bounded ZIP parser.

## Coverage boundaries

ZIP recognition still uses the existing supported prefix gate. A prefixed ZIP
outside that gate reports not evaluated with an explicit unverified-membership
reason, rather than asserting it is not a ZIP. Unsupported reader versions,
malformed headers and invalid filename decoding remain per-attachment errors;
counts unknown to the failed reader are not fabricated as zero.

Successful metadata inventory does not verify member CRCs, local/central header
agreement, decryption, compression support, macro contents or malware absence.
Encrypted/unknown-compression declarations can be inventoried while content
analysis remains unavailable. Macro/type/malware checks and attachment risk scores
keep their explicit unavailable/unknown contracts. No inventory limit/error adds
maliciousness, authentication or attribution points.

New metadata remains in `attachments.json`, the stable case-detail API and sealed
ZIP exports. Historical artifacts remain readable. Sixteen unit tests cover the
reader/name/count/size families and preservation of other attachments. The actual
offline integration uses 14 full CLI cases and five loopback HTTP workers, with
independent standard-parser reconstruction of retained/omitted records and names,
original payload bytes, seals, coverage and exports. Constructed ZIPs are
regression inputs, not classification truth. The private 20-message original EML
corpus has no attachments, so it can test regression of the other analysis paths
but cannot validate real-world ZIP extraction quality.
