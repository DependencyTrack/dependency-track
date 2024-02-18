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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.search.document;

import org.dependencytrack.model.License;

import java.util.UUID;

/**
 * A {@link SearchDocument} for {@link License}s.
 *
 * @param id        ID of the {@link License}
 * @param uuid      {@link UUID} of the {@link License}
 * @param licenseId License ID of the {@link License}
 * @param name      Name of the {@link License}
 * @since 4.10.0
 */
public record LicenseDocument(Long id, UUID uuid, String licenseId, String name) implements SearchDocument {

    public LicenseDocument(final License license) {
        this(license.getId(), license.getUuid(), license.getLicenseId(), license.getName());
    }

}
