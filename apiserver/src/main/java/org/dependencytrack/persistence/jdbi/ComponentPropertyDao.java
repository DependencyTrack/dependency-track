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

import alpine.model.IConfigProperty.PropertyType;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindMethods;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.UUID;

/// @since 5.3.0
@NullMarked
public interface ComponentPropertyDao {

    record ComponentPropertyRow(
            @Nullable String groupName,
            String propertyName,
            @Nullable String propertyValue,
            PropertyType propertyType,
            @Nullable String description,
            UUID uuid) {}

    @SqlQuery("""
        SELECT cp."GROUPNAME"
             , cp."PROPERTYNAME"
             , cp."PROPERTYVALUE"
             , cp."PROPERTYTYPE"
             , cp."DESCRIPTION"
             , cp."UUID"
          FROM "COMPONENT_PROPERTY" AS cp
         INNER JOIN "COMPONENT" AS c
            ON c."ID" = cp."COMPONENT_ID"
         WHERE c."UUID" = :componentUuid
         ORDER BY cp."GROUPNAME"
                , cp."PROPERTYNAME"
                , cp."ID"
        """)
    @RegisterConstructorMapper(ComponentPropertyRow.class)
    List<ComponentPropertyRow> getProperties(@Bind UUID componentUuid);

    @SqlUpdate("""
        INSERT INTO "COMPONENT_PROPERTY" (
          "COMPONENT_ID"
        , "GROUPNAME"
        , "PROPERTYNAME"
        , "PROPERTYVALUE"
        , "PROPERTYTYPE"
        , "DESCRIPTION"
        , "UUID"
        )
        SELECT c."ID"
             , :groupName
             , :propertyName
             , :propertyValue
             , :propertyType
             , :description
             , :uuid
          FROM "COMPONENT" AS c
         WHERE c."UUID" = :componentUuid
           AND NOT EXISTS(
                 SELECT 1
                   FROM "COMPONENT_PROPERTY" AS cp
                  WHERE cp."COMPONENT_ID" = c."ID"
                    AND cp."GROUPNAME" IS NOT DISTINCT FROM :groupName
                    AND cp."PROPERTYNAME" = :propertyName
                    AND cp."PROPERTYVALUE" IS NOT DISTINCT FROM :propertyValue
               )
        """)
    boolean createProperty(@Bind UUID componentUuid, @BindMethods ComponentPropertyRow property);

    @SqlUpdate("""
        DELETE
          FROM "COMPONENT_PROPERTY" AS cp
         USING "COMPONENT" AS c
         WHERE c."ID" = cp."COMPONENT_ID"
           AND c."UUID" = :componentUuid
           AND cp."UUID" = :propertyUuid
        """)
    boolean deleteProperty(@Bind UUID componentUuid, @Bind UUID propertyUuid);
}
