| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-05-18 | [@nscuro](https://github.com/nscuro) |

## Context

Container images have shipped on [Java 25] since September 2025 ([PR #1446]), and CI moved to Java 25 in
January 2026 ([PR #1663]). The compiler release level is still 21, so source code cannot use features added
in 22 through 25. Java 25 is the next LTS after 21 and is stable.

## Decision

Raise the compiler release level to Java 25. Artifacts require Java 25 at runtime.

## Consequences

Operators still on Java 21 must upgrade. Contributor toolchains move to Java 25. Features from 22 through 25
such as stream gatherers, scoped values, flexible constructor bodies, and unnamed pattern variables become
available across the codebase.

[Java 25]: https://openjdk.org/projects/jdk/25/
[PR #1446]: https://github.com/DependencyTrack/hyades-apiserver/pull/1446
[PR #1663]: https://github.com/DependencyTrack/hyades-apiserver/pull/1663
