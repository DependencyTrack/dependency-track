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

import org.dependencytrack.model.ServiceComponent;

import java.util.UUID;

/**
 * A {@link SearchDocument} for {@link ServiceComponent}s.
 *
 * @param id          ID of the {@link ServiceComponent}
 * @param uuid        {@link UUID} of the {@link ServiceComponent}
 * @param group       Group of the {@link ServiceComponent}
 * @param name        Name of the {@link ServiceComponent}
 * @param version     Version of the {@link ServiceComponent}
 * @param description Description of the {@link ServiceComponent}
 * @since 4.10.0
 */
public record ServiceComponentDocument(Long id, UUID uuid, String group, String name, String version,
                                       String description) implements SearchDocument {

    public ServiceComponentDocument(final ServiceComponent service) {
        this(service.getId(), service.getUuid(), service.getGroup(), service.getName(),
                service.getVersion(), service.getDescription());
    }

}
