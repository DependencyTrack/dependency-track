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
package org.dependencytrack.pkghealth;

import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.jdbi.v3.core.Handle;

import static org.dependencytrack.model.ConfigPropertyConstants.PACKAGE_HEALTH_RESOLUTION_ENABLED;

/**
 * Reads the {@code package-health.enabled} setting.
 * <p>
 * When it is off, no package health request leaves the server, and stored health
 * is neither returned by the REST API nor visible to policies.
 *
 * @since 5.2.0
 */
public final class PackageHealthSettings {

    private PackageHealthSettings() {}

    public static boolean isEnabled(final Handle handle) {
        return handle.attach(ConfigPropertyDao.class)
                .getOptionalValue(PACKAGE_HEALTH_RESOLUTION_ENABLED, Boolean.class)
                .orElse(true);
    }
}
