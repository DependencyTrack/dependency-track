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
package org.dependencytrack.plugin.runtime;

import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

/**
 * @since 5.0.0
 */
final class ExtensionConfigDao {

    private final Handle handle;

    ExtensionConfigDao(Handle handle) {
        this.handle = handle;
    }

    boolean exists(String extensionPointName, String extensionName) {
        return handle.createQuery("""
                        SELECT EXISTS(
                          SELECT 1
                            FROM "EXTENSION_RUNTIME_CONFIG"
                           WHERE "EXTENSION_POINT" = :extensionPointName
                             AND "EXTENSION" = :extensionName
                        )
                        """)
                .bind("extensionPointName", extensionPointName)
                .bind("extensionName", extensionName)
                .mapTo(boolean.class)
                .one();
    }

    @Nullable String get(String extensionPointName, String extensionName) {
        return handle.createQuery("""
                        SELECT "CONFIG"
                          FROM "EXTENSION_RUNTIME_CONFIG"
                         WHERE "EXTENSION_POINT" = :extensionPointName
                           AND "EXTENSION" = :extensionName
                        """)
                .bind("extensionPointName", extensionPointName)
                .bind("extensionName", extensionName)
                .mapTo(String.class)
                .findOne()
                .orElse(null);
    }

    boolean save(String extensionPointName, String extensionName, String config) {
        final int modifiedRows = handle.createUpdate("""
                        INSERT INTO "EXTENSION_RUNTIME_CONFIG" ("EXTENSION_POINT", "EXTENSION", "CONFIG", "CREATED_AT")
                        VALUES (:extensionPointName, :extensionName, CAST(:config AS JSONB), NOW())
                        ON CONFLICT ("EXTENSION_POINT", "EXTENSION")
                        DO UPDATE
                        SET "CONFIG" = EXCLUDED."CONFIG"
                          , "UPDATED_AT" = NOW()
                        WHERE "EXTENSION_RUNTIME_CONFIG"."CONFIG" IS DISTINCT FROM EXCLUDED."CONFIG"
                        """)
                .bind("extensionPointName", extensionPointName)
                .bind("extensionName", extensionName)
                .bind("config", config)
                .execute();
        return modifiedRows > 0;
    }

}
