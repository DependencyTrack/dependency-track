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
deleted. It was marked as a duplicate issue of [Issue 877], which asks for
a retention policy for uploaded BOMs.

Maintainer guidance in [Discussion 6133] identifies the same integration
points. Dependency-Track should retain the existing FileStorage object, provide
access to it, and delete it with its project.

The upload API supports several transport formats. It decodes base64 uploads,
decompresses gzip and zstd uploads, and removes a leading byte-order mark before
it stores and processes the BOM. Therefore, the retained object represents the
BOM document that the import processes. It does not preserve the exact HTTP
request body or its transport wrapper.

Retaining BOM documents increases storage use. The amount grows with every
successful retained import. Therefore, a limit or a retention policy needs
to be in place to act as a safeguard to avoid the growth from continuing
without a clear stopping point. Operators need to be aware that there will
still be a storage requirement they need to accept upon using this retention
policy and feature. 

### Possible Solutions

#### BOM Retention Solutions

#### A: Store complete FileStorage metadata on each BOM record

We add a nullable binary column to the `BOM` table. Store the serialized
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

We give each retained document a stable logical name and rebuild its reference
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

We write a small project-specific file that points to the retained object.

*Pros*:

1. BOM content remains outside PostgreSQL.
2. No relational schema change is required.

*Cons*:

1. It adds another non-atomic storage write.
2. Concurrent updates need versioning or compare-and-set behavior that
   FileStorage does not provide.
3. The manifest is derived state that needs repair or reconciliation.

#### BOM Retention Clean-up Solutions

#### E: Dedicated retention workflow

We will create a new workflow that will select the proper files and delete
them through a file deletion step, where each reference is only cleared
after the file is deleted. It processes the file in batches.

*Pros*:

1. A failed deletion keeps its reference, so a later run can try again.
2. A failed deletion does not leave a file in storage without a reference.

*Cons*:

1. It adds a second layer of orchestration on top of the existing file
deletion workflow.
2. If clearing a reference fails after the file is deleted, the reference
points to a missing file.
3. Every retained import would start a workflow run, even when there is
nothing to delete.

#### F: Clear references, reuse asynchronous file deletion

A small database transaction clears the references to the files for deletion,
and returns their metadata. The existing workflow for asynchronous file
deletion is used to delete the appropriate file. Follows the same structure
as project deletion.

*Pros*:

1. It reuses existing workflow and deletion procedures, without adding
overhead.
2. Follows the existing project deletion pattern that already exists.

*Cons*:

1. If deletion fails after retries, the file stays in storage without a
reference.
2. The same happens if the process stops between the commit and scheduling
the deletion.

## Decision

We will follow solution A for BOM storage and file reference, and
solution F for cleanup. We will store the complete serialized FileStorage
`FileMetadata` on the corresponding `BOM` record in a nullable PostgreSQL
`BYTEA` column.

The column will contain metadata only. BOM content will remain in FileStorage.
The metadata includes the provider name, location, media type, digest, and any
additional provider data. Application code will not rebuild a reference from a
filename or from a subset of these fields.

Original BOM retention will be disabled by default. Whether an upload is retained
will be decided when it is accepted and carried with its import workflow. It will
apply only to future uploads and will not backfill existing BOM records.

When retention is enabled, a successful import will associate the metadata of
the existing upload object with the new `BOM` record. The workflow will leave
that object in FileStorage. It will not write a second copy.

Administrators will choose one of two retention policies. Latest-only is the
default. It keeps the retained document of the newest import of each project.
After a retained import commits, the retained documents of older imports of
that project are removed. The new import and any later imports are kept.
Age-based retention keeps retained documents until they reach a configured age.
The age is measured from the import time in whole 24-hour days. A document that
reaches the configured age exactly becomes eligible for removal, and the next
scheduled run removes it. The default is 90 days, and the value must be
positive. The newest document of a project is also removed once it is old
enough. The endpoint then returns not found for that project.

The policy settings will be read when cleanup runs, not when the upload is
accepted. Latest-only cleanup runs after each retained import. Age-based
cleanup runs as a scheduled maintenance task, daily by default. Disabling
retention stops new cleanup, but it does not delete existing documents.
Switching from age-based to latest-only removes the accumulated older documents
of a project at its next retained import. Retention cleanup keeps BOM records
and only clears their reference to the stored document.

When retention is disabled, the workflow will continue deleting the upload
after a successful import. A failed import will delete the upload unless a
committed `BOM` record references it. If the workflow cannot determine whether
such a reference exists, it retains the upload. A failure to create the import
workflow will also trigger a compensating deletion attempt.

The existing V1 upload API will remain the upload path. The document retained
from this path will be the decoded and decompressed BOM document used by the
import. Transport wrappers and a leading byte-order mark will not be retained.

We will write the new field in the JDBI path. New read, cleanup, and deletion
queries will use raw SQL and JDBI, in line with the current persistence guidance.

We will add one spec-first V2 endpoint to the Projects resource. It will return
the newest successfully imported BOM for the requested project that has
retained metadata. The endpoint will require `VIEW_PORTFOLIO` and access to the
project. It will read the metadata in a short database transaction, close that
transaction, and then retrieve the document from FileStorage.

The endpoint will preserve the recorded media type. It will return not found
when the project, retained reference, or stored object does not exist. The
initial endpoint will not list imports or retrieve an older retained document.

Retained documents will share the lifecycle of their project. Manual, batch,
cascade, and maintenance deletion will collect the affected metadata in the
same database statement that deletes the project rows. FileStorage cleanup
will begin only after that transaction commits. It will run asynchronously
in a Dex workflow with retries, not as part of the thread that handles the
request.

Retention cleanup will follow the same idea, a small database 
transaction clears the references and returns their metadata. Afterwards,
the same asynchronous file deletion will be scheduled. A failure of
latest-only cleanup will be logged and will not fail the import. Its
transaction rolls back, so the next retained import of the project
tries again. A failed age-based run keeps its references, and the
next scheduled run tries again.

A missing object during cleanup will be treated as already deleted. Malformed
metadata and other cleanup failures will be logged for manual follow-up. They
will not roll back a committed project deletion or a committed import.

Historical retrieval, per-project retention policies, retention overrides
at upload time, orphan garbage collection, notification references, VEX
retention, historical backfill, and a V2 upload endpoint are outside this
decision.

## Consequences

Users can retrieve the BOM document that Dependency-Track processed instead of
only receiving a newly constructed export. Large BOM content remains outside
PostgreSQL and workflow messages.

The database gains one nullable column. Existing rows remain valid. No backfill
is required. Age-based cleanup filters on the import time without a
dedicated index. An index can be added if measurements show a need.

Each successful opted-in import adds one retained FileStorage object and one
small metadata value. The retention policies are meant to limit how much of
this storage stays in use. With latest-only retention, each project will
normally store one document. With age-based retention, storage use depends
on how often the projects receive uploads and on the configured number of
days. The initial API exposes only the newest retained document for each
project. Older files retained with age-based retention cannot be retrieved
by the API yet. Operators must plan storage capacity and retention around this
behavior.

Database and FileStorage operations remain non-atomic. A reference can point
to a missing object. A crash can also leave an object with no database
reference. The endpoint and cleanup paths must tolerate these states, as
required by [ADR 004].

Project deletion and retention cleanup will make their database changes final
before they delete files. A cleanup failure can therefore leave an
orphaned object without a reference, if the deletion fails after all retries
or if an import commits while its project is being deleted. The
deletion statement does not see the new import record, but the database
still removes that record with the project. This consumes storage but it
cannot restore or partially restore the deleted project. A future garbage
collector or provider retention policy may remove such objects.

A failed import now checks the database before it deletes its upload. This
adds one database query to the failure path of retained imports.

Retained documents remain tied to the FileStorage provider that created them.
Changing providers can make older documents unavailable unless their content
and metadata are migrated.

Retaining original documents increases the amount of potentially sensitive
project data at rest. Operators must apply suitable access controls,
encryption, backups, and lifecycle policies to their FileStorage provider.

[ADR 004]: ./004-file-storage-plugin.md
[Discussion 6133]: https://github.com/DependencyTrack/dependency-track/discussions/6133#discussioncomment-16909921
[Issue 877]: https://github.com/DependencyTrack/dependency-track/issues/877
[Issue 7516]: https://github.com/DependencyTrack/dependency-track/issues/7516
[PR 7527]: https://github.com/DependencyTrack/dependency-track/pull/7527#discussion_r4287252393
