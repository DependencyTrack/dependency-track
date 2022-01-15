/*
 * Copyright 2022 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.dependencytrack.resources.v1.vo;

import alpine.model.Permission;
import alpine.model.Team;
import java.util.List;
import java.util.UUID;
import javax.annotation.Nonnull;

/**
 * Response-Object that contains only a subset of a {@link Team}
 * 
 * @author Ronny "Sephiroth" Perinke <sephiroth@sephiroth-j.de>
 * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/861">gh-issue 861</a>
 */
public final class TeamSelfResponse {
    
    private final UUID uuid;
    private final String name;
    private final List<Permission> permissions;

    public TeamSelfResponse(@Nonnull final Team source) {
        uuid = source.getUuid();
        name = source.getName();
        permissions = source.getPermissions();
    }

    public UUID getUuid() {
        return uuid;
    }

    public String getName() {
        return name;
    }

    public List<Permission> getPermissions() {
        return permissions;
    }
}
