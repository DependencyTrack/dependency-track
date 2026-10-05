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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.RepositoryType;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * @since 5.2.0
 */
@NullMarked
public interface RepositoryDao {

    /**
     * @return Enabled repositories of the given type, in resolution order
     */
    @SqlQuery("""
        SELECT "TYPE"
             , "IDENTIFIER"
             , "URL"
             , "INTERNAL"
             , "AUTHENTICATIONREQUIRED"
             , "USERNAME"
             , "PASSWORD"
          FROM "REPOSITORY"
         WHERE "TYPE" = :type
           AND "ENABLED"
         ORDER BY "RESOLUTION_ORDER"
        """)
    @RegisterConstructorMapper(EnabledRepository.class)
    List<EnabledRepository> getEnabledRepositories(@Bind RepositoryType type);

    /**
     * @param password Reference to the secret that holds the password or token
     */
    record EnabledRepository(
            RepositoryType type,
            String identifier,
            String url,
            @Nullable Boolean internal,
            boolean authenticationRequired,
            @Nullable String username,
            @Nullable String password) {}
}
