| Status   | Date       | Author(s)                                                |
|:---------|:-----------|:---------------------------------------------------------|
| Proposed | 2026-09-23 | [@cartermitchellLM](https://github.com/cartermitchellLM) |

## Context

Presently in the tool, a component is by default considered to have one license associated to
it if it is not utilizing SPDX License Expressions. The default selection is done by taking the
first license present in the imported BOM and discarding the rest. This is does not support all
use cases in that some components do have multiple licenses that apply and not every user will
be making use of SPDX License Expressions. It is also unclear to users that the other licenses
in the uploaded BOM are being discarded, i.e. not stored in the database.

## Decision

We will extract the license data associated to a component into its own table to solve this data loss.
There is already precedence for doing so with vulnerabilities (see: the `COMPONENTS_VULNERABILITIES`
table). The `COMPONENTS` table will lose its license related columns as well as its foreign key
constraint to the `LICENSE` table, shifting them all to a table called `COMPONENTLICENSES`.

The `COMPONENTLICENSES` will house all of that old data with the addition of two columns: `CONCLUDED`
and `ORDINALITY`. The `CONCLUDED` column will allow for future implementation of users accepting
licenses as concluded, but presently will populate by default with a value of `false`. The `ORDINALITY`
column will preserve the current functionality of assuming the licenses coming from the BOM are ordered.

In the future, a new API endpoint will be added to pull all licenses for a given component, and the 
frontend will be updated to allow viewing of all the available licenses.

## Consequences

Most of the changes necessitated by this schema change are not user facing, but will
allow for easier implementation of future license related features.

One downside of this change is that SQL queries and testing license related functionality 
will become more complex due to the need to write a join for any kind of query that requires 
licensing data and the need to insert into another table when testing.