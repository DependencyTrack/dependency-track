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
package org.dependencytrack.policy.cel.persistence;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.persistence.jdbi.mapping.OptionalColumnRowMapper;
import org.dependencytrack.proto.policy.v1.License;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

@NullMarked
public final class CelPolicyLicenseRowMapper implements OptionalColumnRowMapper<License> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CelPolicyLicenseRowMapper.class);

    @Override
    public License map(ResultSet rs, StatementContext ctx, Columns columns) throws SQLException {
        final License.Builder builder = License.newBuilder();
        columns.maybeSet(rs, "uuid", ResultSet::getString, builder::setUuid);
        columns.maybeSet(rs, "id", ResultSet::getString, builder::setId);
        columns.maybeSet(rs, "name", ResultSet::getString, builder::setName);
        columns.maybeSet(rs, "is_osi_approved", ResultSet::getBoolean, builder::setIsOsiApproved);
        columns.maybeSet(rs, "is_fsf_libre", ResultSet::getBoolean, builder::setIsFsfLibre);
        columns.maybeSet(rs, "is_deprecated_id", ResultSet::getBoolean, builder::setIsDeprecatedId);
        columns.maybeSet(rs, "is_custom", ResultSet::getBoolean, builder::setIsCustom);
        columns.maybeSet(
                rs, "groups_json", ResultSet::getString, jsonString -> parseLicenseGroups(builder, jsonString));
        return builder.build();
    }

    private static void parseLicenseGroups(License.Builder builder, @Nullable String jsonString) {
        if (jsonString == null) {
            return;
        }

        try {
            final ArrayNode groupsArray = Mappers.jsonMapper().readValue(jsonString, ArrayNode.class);
            for (final JsonNode groupNode : groupsArray) {
                builder.addGroups(License.Group.newBuilder()
                        .setUuid(Optional.ofNullable(groupNode.get("uuid"))
                                .map(JsonNode::asText)
                                .orElse(""))
                        .setName(Optional.ofNullable(groupNode.get("name"))
                                .map(JsonNode::asText)
                                .orElse(""))
                        .build());
            }
        } catch (JacksonException e) {
            LOGGER.warn("Failed to parse license groups from {}", jsonString, e);
        }
    }
}
