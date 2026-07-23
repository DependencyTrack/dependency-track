# Nullability

We use [JSpecify] annotations to declare nullability, enforced at compile time by [NullAway].
This practice was introduced via [ADR 031].

## Rules

* Every new package **must** have a `package-info.java` annotated with `@NullMarked`.
  NullAway is only enforced in packages with `@NullMarked`-annotated `package-info.java`.
* Inside a `@NullMarked` package, every type is non-null by default.
  Mark nullable types with `@Nullable` from `org.jspecify.annotations`.
* Do not use other nullability annotations (`javax.annotation`, `jakarta.annotation`, JetBrains, etc.).

## New package template

```java
/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
@NullMarked
package org.dependencytrack.example;

import org.jspecify.annotations.NullMarked;
```

## References

* [JSpecify user guide](https://jspecify.dev/docs/user-guide/)
* [NullAway wiki](https://github.com/uber/NullAway/wiki)

[ADR 031]: adr/031-enforce-jspecify-nullness-with-nullaway.md
[JSpecify]: https://jspecify.dev/
[NullAway]: https://github.com/uber/NullAway