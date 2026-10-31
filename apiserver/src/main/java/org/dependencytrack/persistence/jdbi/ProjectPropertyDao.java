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
@RegisterConstructorMapper(ProjectPropertyDao.ProjectPropertyRow.class)
public interface ProjectPropertyDao {

    record ProjectPropertyRow(
            String groupName,
            String propertyName,
            @Nullable String propertyValue,
            PropertyType propertyType,
            @Nullable String description) {}

    @SqlQuery("""
        SELECT pp."GROUPNAME"
             , pp."PROPERTYNAME"
             , pp."PROPERTYVALUE"
             , pp."PROPERTYTYPE"
             , pp."DESCRIPTION"
          FROM "PROJECT_PROPERTY" AS pp
         INNER JOIN "PROJECT" AS p
            ON p."ID" = pp."PROJECT_ID"
         WHERE p."UUID" = :projectUuid
         ORDER BY pp."GROUPNAME"
                , pp."PROPERTYNAME"
        """)
    List<ProjectPropertyRow> getProperties(@Bind UUID projectUuid);

    @SqlQuery("""
        SELECT pp."GROUPNAME"
             , pp."PROPERTYNAME"
             , pp."PROPERTYVALUE"
             , pp."PROPERTYTYPE"
             , pp."DESCRIPTION"
          FROM "PROJECT_PROPERTY" AS pp
         INNER JOIN "PROJECT" AS p
            ON p."ID" = pp."PROJECT_ID"
         WHERE p."UUID" = :projectUuid
           AND pp."GROUPNAME" = :groupName
           AND pp."PROPERTYNAME" = :propertyName
        """)
    @Nullable
    ProjectPropertyRow getProperty(@Bind UUID projectUuid, @Bind String groupName, @Bind String propertyName);

    @SqlUpdate("""
        INSERT INTO "PROJECT_PROPERTY" (
          "PROJECT_ID"
        , "GROUPNAME"
        , "PROPERTYNAME"
        , "PROPERTYVALUE"
        , "PROPERTYTYPE"
        , "DESCRIPTION"
        )
        SELECT "ID"
             , :groupName
             , :propertyName
             , :propertyValue
             , :propertyType
             , :description
          FROM "PROJECT"
         WHERE "UUID" = :projectUuid
        ON CONFLICT ("PROJECT_ID", "GROUPNAME", "PROPERTYNAME") DO NOTHING
        """)
    boolean createProperty(@Bind UUID projectUuid, @BindMethods ProjectPropertyRow property);

    @SqlUpdate("""
        UPDATE "PROJECT_PROPERTY" AS pp
           SET "PROPERTYVALUE" = :propertyValue
          FROM "PROJECT" AS p
         WHERE p."ID" = pp."PROJECT_ID"
           AND p."UUID" = :projectUuid
           AND pp."GROUPNAME" = :groupName
           AND pp."PROPERTYNAME" = :propertyName
        """)
    void updatePropertyValue(@Bind UUID projectUuid, @BindMethods ProjectPropertyRow property);

    @SqlUpdate("""
        DELETE
          FROM "PROJECT_PROPERTY" AS pp
         USING "PROJECT" AS p
         WHERE p."ID" = pp."PROJECT_ID"
           AND p."UUID" = :projectUuid
           AND pp."GROUPNAME" = :groupName
           AND pp."PROPERTYNAME" = :propertyName
        """)
    boolean deleteProperty(@Bind UUID projectUuid, @Bind String groupName, @Bind String propertyName);
}
