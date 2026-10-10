# MIME tree header inventory

New CLI/API cases include the sealed `mime_header_inventory.json` artifact.
The existing top-level inventory remains available with its original schema.
The new artifact preserves ordered, duplicate and unknown header observations
for every retained node in the existing email parser tree, including multipart
containers, supported/unsupported content, inline parts, attachments and nodes
below encapsulated messages. It does not decode or execute their content.

## Identity and claim scope

Preorder `part_id` values start at `0` and append zero-based child indices.
`parent_part_id` and `depth` describe parser ancestry. `message_root_part_id`
and `enclosing_message_part_id` distinguish fields below each message container
from the outer message's fields. A child of `message/rfc822` is labeled
`encapsulated_message`; children of other `message/*` types are explicitly
`parser_message_block`, including delivery-status blocks and `message/global`.
Those labels describe parser interpretation, not conformance, authenticity or
successful transfer decoding of a nested email. An unsupported transfer encoding
may leave a parser child with no recognized headers.

`outer_mime_part_id` links each observation to the existing outer MIME inventory.
For descendants of a message container, it stays on the first outer message
container, whose existing attachment representation remains authoritative.
Nested messages retain their immediate enclosing/root IDs as separate context.
No inner From, Received or Authentication-Results value becomes an outer sender
claim, verified authentication, a scored signal or an outer body URL.

Each node contains the same field contract as the
[top-level inventory](header-inventory.md), with scope
`parser_recognized_entity_headers`: order, occurrence within each case-insensitive
name, raw parser-value octets in base64, independently derived text and defects.
Occurrence counts restart per node. Source path/SHA256 refer to the unchanged
whole `input.eml`, not a serialized nested message. Raw values are not exact
field byte spans; `input.eml` remains the original byte evidence. Header-looking
body text and malformed lines not recognized as headers are not invented as
fields. Inventory occurs before body decoding can add defects to parser nodes.

## Budgets and status

Default inventory limits are:

| Resource | Limit |
| --- | ---: |
| Retained parser nodes / depth | 500 / 30 |
| Fields per node / entire tree, including root | 1,024 / 4,096 |
| Field name / raw value | 256 / 16,384 bytes |
| Captured raw names and values per node / tree | 262,144 / 1,048,576 bytes |
| Captured derived text across tree | 2,097,152 UTF-8 bytes |

The existing 25 MiB input and 500-node parser bounds remain in force. Traversal
also enforces depth 30 below message containers; previously the outer MIME walk
stopped at these containers. Exceeding those hard bounds fails analysis before
case ingestion. Lower inventory-specific node/depth limits used through Python
produce explicit omissions while still counting the bounded full parser tree.
The supervised worker's execution/memory bounds apply to parsing and extraction.

No truncated field is emitted as complete. Field-count exhaustion retains counts;
raw/value limits retain positions and null unavailable values; a derived-byte
limit preserves captured raw values and records `parsed_byte_budget`. Remaining
budgets span nodes, including zero remaining fields/raw/derived bytes. A later
smaller value can still fit. Names count toward captured raw bytes; derived bytes
are measured after UTF-8 sanitization. Per-field derived character and defect
limits remain those of the top-level inventory.

Node defects, omitted fields/nodes, unavailable raw/derived views and capture
limits make coverage partial. Completed means observations were retained within
this parser/extraction scope, not successful body decoding, exhaustive byte-level
MIME interpretation, authenticated claims or completed active analysis.

## Integration and measured scope

`mime_header_inventory` is an additive coverage stage and stable API detail key.
The technical report references counts and the artifact, without rendering
arbitrary header values. Normal sealing and ZIP export include the artifact;
historical cases without it remain readable. Selected outer headers, body and
attachment representations, scoring and the index keep their existing contracts.

The private source audit of 20 original EMLs found 44 parser nodes, 1,180 outer
fields and 48 additional part fields: 24 Content-Type and 24 transfer-encoding
declarations. Those declarations were already used as selected MIME metadata;
the new artifact additionally preserves their full ordered field observations.
This corpus has no attachments or nested emails. It cannot establish nested
message extraction quality or classification accuracy.

Sixteen unit tests cover ancestry, duplicates, octets, parser message blocks,
malformed/headerless nodes, global/per-node budgets, zero remaining budgets,
hard limits, encoded message non-decoding and absence of body-decoding side effects. The actual integration
runs 12 supervised `full --no-egress` CLI cases and three loopback HTTP workers:
multipart alternatives, inline/text attachments, two levels of RFC822 messages,
implicit digest content, delivery/external/global blocks, unknown types,
malformed/encoded/high-octet fields and global raw/derived/field exhaustion.
Expected observations are reconstructed with the standard parser independently
of PAW's inventory/traversal. Originals, seals, API/ZIP, coverage and separation
of embedded sender/authentication/URL claims are checked. Constructed fixtures
are regression inputs, not classification labels. No sample URL/DNS access,
attachment execution or active content rendering is performed.
