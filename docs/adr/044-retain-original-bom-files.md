| Status   | Date       | Author(s)                                              |
|:---------|:-----------|:-------------------------------------------------------|
| Proposed | 2026-09-30 | [@elias-chevere](https://github.com/elias-chevere) |

## Context

Dependency-Track imports CycloneDX BOM documents into its relational model.
The upload flow first stores the document in FileStorage so that an asynchronous
workflow can process it. The workflow deletes the stored document after the
import finishes.

When a user later exports a BOM, Dependency-Track builds a new document from
the relational model. The exported document is not necessarily the document
that Dependency-Track processed. Some users need to retrieve the processed
document for audit, compliance, comparison, or downstream processing.

BOM documents can be tens or hundreds of MiB. Storing them in PostgreSQL or in
workflow messages would work against the large-file boundary established by
[ADR 004]. FileStorage already stores the document once during upload. The
missing part is a durable relationship between a successful BOM import and
that stored object.

[Issue 7516] requests opt-in retention of the BOM document used for import,
authorized retrieval of that document, and cleanup when its project is
deleted.

Maintainer guidance in [Discussion 6133] identifies the same integration
points. Dependency-Track should retain the existing FileStorage object, provide
access to it, and delete it with its project.

The upload API supports several transport formats. It decodes base64 uploads,
decompresses gzip and zstd uploads, and removes a leading byte-order mark before
it stores and processes the BOM. Therefore, the retained object represents the
BOM document that the import processes. It does not preserve the exact HTTP
request body or its transport wrapper.

Retaining BOM documents increases storage use. The amount grows with every
successful retained import until its project is deleted. Operators need to
choose whether to accept this cost.

### Possible Solutions

#### A: Store complete FileStorage metadata on each BOM record

Add a nullable binary column to the `BOM` table. Store the serialized
FileStorage `FileMetadata` protobuf after a successful retained import.

*Pros*:

1. The BOM import record owns the reference to its retained document.
2. The existing upload object can be retained without storing a second copy.
3. All metadata needed by the storage provider remains available.
4. Existing rows and imports with retention disabled need no backfill.

*Cons*:

1. A database migration and a change to the legacy JDO model are required.
2. Database and FileStorage operations cannot be atomic.
3. A database reference can point to a file that no longer exists.

#### B: Derive the reference from a FileStorage name

Give each retained document a stable logical name and rebuild its reference
when the document is downloaded or deleted.

*Pros*:

1. No database schema change is required.

*Cons*:

1. [ADR 004] does not require a provider to preserve the supplied name.
2. FileStorage retrieves and deletes objects through complete metadata, not a
   logical name.
3. Rebuilding a provider URI would couple application code to storage
   providers.
4. Concurrent imports would need overwrite and retry rules.

#### C: Add logical-name lookup to FileStorage

Extend the FileStorage API and its providers with a lookup or move operation.

*Pros*:

1. The application could use a provider-neutral logical name.
2. No database schema change is required.

*Cons*:

1. It changes a cross-module extension point for one product use case.
2. Every current and future provider inherits the new contract.
3. The contract needs rules for overwrites, retries, concurrent imports, and
   storage provider changes.
4. FileStorage would become an application index even though [ADR 004] says it
   is not the primary system of record.

#### D: Store a pointer manifest in FileStorage

Write a small project-specific file that points to the retained object.

*Pros*:

1. BOM content remains outside PostgreSQL.
2. No relational schema change is required.

*Cons*:

1. It adds another non-atomic storage write.
2. Concurrent updates need versioning or compare-and-set behavior that
   FileStorage does not provide.
3. The manifest is derived state that needs repair or reconciliation.

## Decision

We will follow solution A. We will store the complete serialized FileStorage
`FileMetadata` on the corresponding `BOM` record in a nullable PostgreSQL
`BYTEA` column.

The column will contain metadata only. BOM content will remain in FileStorage.
The metadata includes the provider name, location, media type, digest, and any
additional provider data. Application code will not rebuild a reference from a
filename or from a subset of these fields.

Original BOM retention will be disabled by default. The setting will be read
when an upload is accepted and carried with that import workflow. It will apply
only to future uploads and will not backfill existing BOM records.

When retention is enabled, a successful import will associate the metadata of
the existing upload object with the new `BOM` record. The workflow will leave
that object in FileStorage. It will not write a second copy. Every successful
import accepted with retention enabled will be retained.

When retention is disabled, the workflow will continue deleting the upload
after a successful import. A failed import will attempt to delete the upload
regardless of the retention setting. A failure to create the import workflow
will also trigger a compensating deletion attempt.

The existing V1 upload API will remain the upload path. The document retained
from this path will be the decoded and decompressed BOM document used by the
import. Transport wrappers and a leading byte-order mark will not be retained.

We will use the existing JDO import path to write the new field. New read and
deletion queries will use raw SQL and JDBI, in line with the current persistence
guidance.

We will add one spec-first V2 endpoint to the Projects resource. It will return
the newest successfully imported BOM for the requested project that has
retained metadata. The endpoint will require `VIEW_PORTFOLIO` and access to the
project. It will read the metadata in a short database transaction, close that
transaction, and then retrieve the document from FileStorage.

The endpoint will preserve the recorded media type. It will return not found
when the project, retained reference, or stored object does not exist. The
initial endpoint will not list imports or retrieve an older retained document.
Older retained documents will remain stored until their project is deleted.

Retained documents will share the lifecycle of their project. Manual, batch,
cascade, and maintenance deletion will collect all affected metadata in the
same database transaction that deletes the project rows. FileStorage cleanup
will begin only after that transaction commits.

A missing object during cleanup will be treated as already deleted. Malformed
metadata and other cleanup failures will be logged for manual follow-up. They
will not roll back a committed project deletion.

Historical retrieval, deleting older documents when a new import succeeds,
orphan garbage collection, notification references, VEX retention, historical
backfill, and a V2 upload endpoint are outside this decision.

## Consequences

Users can retrieve the BOM document that Dependency-Track processed instead of
only receiving a newly constructed export. Large BOM content remains outside
PostgreSQL and workflow messages.

The database gains one nullable column. Existing rows remain valid. No index or
backfill is required.

Each successful opted-in import adds one retained FileStorage object and one
small metadata value. Storage use can grow without a per-project limit. The
initial API exposes only the newest retained document for each project even
though older retained documents continue to consume storage. Operators must
plan storage capacity and retention around this behavior.

Database and FileStorage operations remain non-atomic. A reference can point
to a missing object. A crash can also leave an object with no database
reference. The endpoint and cleanup paths must tolerate these states, as
required by [ADR 004].

Project deletion will make its database changes final before it attempts file
cleanup. A cleanup failure can therefore leave an orphaned object, but it
cannot restore or partially restore the deleted project. A future garbage
collector or provider retention policy may remove orphans if operational
evidence justifies that work.

Retained documents remain tied to the FileStorage provider that created them.
Changing providers can make older documents unavailable unless their content
and metadata are migrated.

Retaining original documents increases the amount of potentially sensitive
project data at rest. Operators must apply suitable access controls,
encryption, backups, and lifecycle policies to their FileStorage provider.

[ADR 004]: ./004-file-storage-plugin.md
[Discussion 6133]: https://github.com/DependencyTrack/dependency-track/discussions/6133#discussioncomment-16909921
[Issue 7516]: https://github.com/DependencyTrack/dependency-track/issues/7516
