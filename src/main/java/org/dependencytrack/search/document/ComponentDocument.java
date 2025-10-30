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
package org.dependencytrack.search.document;

import org.dependencytrack.model.Component;

import java.util.UUID;

/**
 * A {@link SearchDocument} for {@link Component}s.
 *
 * @param id          ID of the {@link Component}
 * @param uuid        {@link UUID} of the {@link Component}
 * @param group       Group of the {@link Component}
 * @param name        Name of the {@link Component}
 * @param version     Version of the {@link Component}
 * @param description Description of the {@link Component}
 * @param sha1        SHA1 hash of the {@link Component}
 * @since 4.10.0
 */
public record ComponentDocument(Long id, UUID uuid, String group, String name, String version,
                                String description, String sha1) implements SearchDocument {

    public ComponentDocument(final Component component) {
        this(component.getId(), component.getUuid(), component.getGroup(), component.getName(),
                component.getVersion(), component.getDescription(), component.getSha1());
    }

}
