| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-09-14 | [@nscuro](https://github.com/nscuro) |

## Context

API keys do not expire. A leaked key works until someone deletes it.
Keys that nobody uses any more also keep working, and they pile up because nothing forces a review.

[ADR 040](./040-service-accounts.md) introduced service accounts in 5.2.0, so their keys are new.
Team keys have existed for years, and many integrations use keys that were created once and never touched again.

### Standards and guidelines

The following sources are relevant:

* The [OWASP Application Security Verification Standard][ASVS] (ASVS) 5.0.0. It covers how an application
  authenticates clients, logs, and handles errors. It has no requirement for the expiry of API keys an application issues.
* The [OWASP Non-Human Identities Top 10][owasp-nhi] (NHI) 2025, which lists risks of credentials used by machines.
* The [OWASP Secrets Management Cheat Sheet][owasp-secrets].
* [NIST SP 800-53][nist-800-53] Rev. 5, Release 5.2.0, a catalog of security controls.

They say the following:

* **Expiry.** NHI7:2025 lists "API keys [...] with expiration dates that are too far in the future or that don't expire at all"
  as a risk. The Secrets Management Cheat Sheet says "You should create secrets to expire after a defined time where possible".
  NIST SP 800-53 control IA-5 requires refreshing authenticators of people, services, and devices after an
  "organization-defined time period".
* **Lifetime.** No source gives a number. NIST SP 800-53 leaves the period to the organization.
* **Expired keys.** ASVS does not say whether to keep or delete them.
  The Secrets Management Cheat Sheet asks to audit "attempts to reuse expired secrets".
* **Logging.** ASVS 16.3.1 (level 2) requires that "all authentication operations are logged,
  including successful and unsuccessful attempts". ASVS 16.2.5 (level 2) does not allow credentials in logs.
* **Error responses.** ASVS 16.5.1 (level 2) requires that "a generic message is returned to the consumer
  when an unexpected or security-sensitive error occurs".
* **Warning before expiry.** ASVS 6.4.5 (level 3) requires sending renewal instructions
  "with enough time to be carried out before the old authentication mechanism expires".

## Decision

Every API key gets an optional expiry timestamp. Expired keys remain until someone deletes them.
Administrators can see which keys expired, and authentication can log expiry as the reason instead
of reporting an unknown key.

Authentication rejects a key once its expiry has passed. The check runs only after the secret has matched.
The audit log records a security failure with the key's public ID and the time it expired, as ASVS 16.3.1 requires.

The client gets the same `401` as for any other invalid key, as ASVS 16.5.1 requires.
Only the audit log records that the key expired.

### Service account keys

Every new service account key must have an expiry. Service account keys are new, so this breaks no existing integration.
It defaults to 30 days, or the maximum lifetime if that is shorter, and clients can specify any value up to the maximum lifetime.

### Maximum lifetime

The maximum lifetime is 366 days by default, so a client that specifies "one year" does not fail in a leap year.
Operators can change it with the `dt.api-key.max-lifetime-days` property. As NIST SP 800-53 expects,
the organization that runs Dependency-Track decides the period. There is no value for "never".
A new maximum applies to new keys only.

### Team keys

Team keys do not get an expiry. Existing and new team keys keep working without one.
Service accounts replace team keys for integrations, and expiry is one reason to move to them.
This ADR does not deprecate team keys, and does not change how they work.

### Out of scope

* Warning owners before a key expires (ASVS 6.4.5).
* Extending the expiry of an existing key.
* Short-lived credentials without API keys. Workload identity federation will add them, see [#7056][gh-issue-7056].

## Consequences

* A leaked service account key stops working when it expires, even if nobody notices the leak.
* Integrations that use service account keys must rotate them, or fail with `401`.
* The response does not tell the owner of a failing integration that the key expired.
  They have to check the key's expiry in the key list, or ask an administrator to search the audit log.
* Dependency-Track does not meet ASVS 6.4.5 until it warns owners before a key expires.
* Dependency-Track does not fully meet ASVS 16.3.1, because it does not log successful authentications with API keys.
* Team keys never expire, and operators cannot make them expire. They remain the long-lived keys described in the context.
* Moving an integration to a service account is manual. Someone has to create the service account and its key,
  update the integration, and delete the team key.
* Clients cannot see the maximum lifetime. They learn about it only when the server rejects a value.

[ASVS]: https://github.com/OWASP/ASVS/tree/v5.0.0/5.0
[gh-issue-7056]: https://github.com/DependencyTrack/dependency-track/issues/7056
[nist-800-53]: https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_2_0/home
[owasp-nhi]: https://owasp.github.io/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/
[owasp-secrets]: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
