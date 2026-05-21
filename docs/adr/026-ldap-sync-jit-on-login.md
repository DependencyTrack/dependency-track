| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-05-21 | [@nscuro](https://github.com/nscuro) |

## Context

LDAP users are refreshed by a scheduled task that iterates every locally
known LDAP user on each execution and re-queries the directory per user.
The task also marks users that have disappeared from LDAP as invalid.

The model is opaque to operators. Newly provisioned users are persisted
with a `Syncing...` DN placeholder, but nothing in the UI indicates when
the next sync will run. Users see a state they cannot reason about.
The existing-user path during login returns the cached row unchanged,
so most of the sync responsibilities are only covered between cron executions.
The auto-provision path at the first login already performs the same refresh inline.

OIDC, the recommended primary external identity source, refreshes
attributes purely at login. There is no background pull.
We want the same model for LDAP.

## Decision

Refresh LDAP attributes at login time. After credentials have been
validated, the login flow performs one directory lookup for the
authenticated user and updates the cached DN, email, and (when team
synchronization is enabled) team membership. Refresh failures are logged
and swallowed. Credentials have already been validated, so a directory
hiccup must not turn a valid login into a failure.

The scheduled sync task and its supporting wiring are removed entirely.
The `Syncing...` DN placeholder is also removed. New LDAP users are
persisted with a null DN and email, populated on first successful login.
This matches how OIDC users are provisioned: their subject identifier and
email are left null until the first sign-in. The schema CHECK constraint
on `USER.DN` is relaxed accordingly via a Flyway migration.

The associated cron and lock-duration configuration keys are removed.
Operators with these set in their config will see startup warnings about
unknown keys and can drop them.

The invalid marker for users removed from the directory is dropped. There
is no natural login-time hook for it. Authentication still fails for
removed users because the credential bind step does not find them in the
directory, so this is a janitorial gap, not a security gap.
A follow-up may add an admin-triggered cleanup endpoint.

For reference, Keycloak supports both on-demand (JIT) and periodic
background synchronization for its LDAP federation, per the
[Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html#synchronizing-ldap-users-to-keycloak).
We choose JIT-only and do not provide the periodic complement. OIDC has
no equivalent today, and cannot have one in the general case: the OIDC
specification gives the relying party no mechanism to enumerate users at
the provider or poll for attribute changes between logins. JIT-on-login
is the only model available there, so unifying LDAP onto it is also the
only way to share one operational story across both sources.

## Consequences

Operational complexity drops sharply. Removing the task removes a whole
class of inconsistencies and coordination requirements: no cron tuning,
no distributed lock to hold while the task runs, no events to fan out, no
race between provisioning and the next sync execution, no test scaffolding for
a background task that does not exist in test runs. Every change to LDAP
user state is now a direct consequence of an action the operator can see.

Operators no longer see a misleading `Syncing...` placeholder. A null DN
clearly reflects "not yet seen by the server", consistent with how OIDC
users look before their first sign-in.

Each successful login performs one extra directory lookup, plus a group
lookup when team sync is enabled. The cost matches today's auto-provision
path and is negligible for session-token UX.

Users who never log in keep frozen attributes at provision time. Users
removed from LDAP keep a stale local row until an admin deletes it. Both
are accepted regressions and are noted in the release notes.
