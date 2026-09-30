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
package alpine.model.auth;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

/// @since 5.2.0
public sealed interface Principal extends java.security.Principal permits ApiKeyPrincipal, UserPrincipal {

    /// @return A human-readable identification of the principal, for logging and auditing.
    String displayName();

    /// @return The teams the principal is a member of, ordered by name.
    List<TeamRef> teams();

    /// @return Names of all permissions the principal has, directly or through its teams.
    Set<String> effectivePermissions();

    /// @param permission Name of the permission to check for.
    /// @return Whether the principal has {@code permission}, directly or through a team.
    default boolean hasPermission(String permission) {
        return effectivePermissions().contains(permission);
    }

    /// @param permissions Names of the permissions to check for.
    /// @return Whether the principal has any of {@code permissions}, directly or through a team.
    default boolean hasAnyPermission(String... permissions) {
        return Arrays.stream(permissions).anyMatch(this::hasPermission);
    }

    /// @deprecated Only present to satisfy [java.security.Principal]. Use [#displayName()] instead.
    @Deprecated
    @Override
    default String getName() {
        return displayName();
    }
}
