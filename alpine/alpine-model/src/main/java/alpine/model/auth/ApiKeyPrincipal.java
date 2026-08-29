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

import alpine.model.ApiKey;

import java.util.List;
import java.util.Set;

/// @since 5.2.0
public record ApiKeyPrincipal(long id, String publicId, List<TeamRef> teams, Set<String> effectivePermissions)
        implements Principal {

    public ApiKeyPrincipal {
        teams = List.copyOf(teams);
        effectivePermissions = Set.copyOf(effectivePermissions);
    }

    /// @return The masked key.
    public String maskedKey() {
        return ApiKey.PREFIX + publicId + "*".repeat(ApiKey.API_KEY_LENGTH);
    }

    @Override
    public String displayName() {
        return maskedKey();
    }
}
