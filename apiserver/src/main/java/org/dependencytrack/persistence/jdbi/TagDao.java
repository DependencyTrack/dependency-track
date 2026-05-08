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

import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

/**
 * @since 5.0.0
 */
public interface TagDao extends SqlObject {

    @SqlUpdate("""
            DELETE
              FROM "TAG"
             WHERE NOT EXISTS(
                 SELECT 1
                   FROM "PROJECTS_TAGS"
                  WHERE "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID")
               AND NOT EXISTS(
                  SELECT 1
                    FROM "POLICY_TAGS"
                   WHERE "POLICY_TAGS"."TAG_ID" = "TAG"."ID")
               AND NOT EXISTS(
                  SELECT 1
                    FROM "VULNERABILITIES_TAGS"
                   WHERE "VULNERABILITIES_TAGS"."TAG_ID" = "TAG"."ID")
            """)
    int deleteUnused();

}
