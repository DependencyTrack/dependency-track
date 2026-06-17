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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.protobuf.util.JsonFormat;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.model.mapping.PolicyProtoMapper;
import org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Tools;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.result.UnableToProduceResultException;
import org.jdbi.v3.core.statement.StatementContext;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public final class CelPolicyProjectRowMapper implements RowMapper<Project> {

    private static final JsonFormat.Parser PROPERTY_JSON_PARSER =
            JsonFormat.parser().ignoringUnknownFields();

    @Override
    public Project map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Project.Builder builder = Project.newBuilder();
        maybeSet(rs, "uuid", ResultSet::getString, builder::setUuid);
        maybeSet(rs, "group", ResultSet::getString, builder::setGroup);
        maybeSet(rs, "name", ResultSet::getString, builder::setName);
        maybeSet(rs, "version", ResultSet::getString, builder::setVersion);
        maybeSet(rs, "classifier", ResultSet::getString, builder::setClassifier);
        maybeSet(rs, "cpe", ResultSet::getString, builder::setCpe);
        maybeSet(rs, "purl", ResultSet::getString, builder::setPurl);
        maybeSet(rs, "swid_tag_id", ResultSet::getString, builder::setSwidTagId);
        maybeSet(rs, "last_bom_import", RowMapperUtil::nullableTimestamp, builder::setLastBomImport);
        maybeSet(rs, "tags", RowMapperUtil::stringArray, builder::addAllTags);
        maybeSet(rs, "properties", CelPolicyProjectRowMapper::maybeConvertProperties, builder::addAllProperties);

        final Project.Metadata.Builder metadataBuilder = Project.Metadata.newBuilder();
        maybeSet(rs, "metadata_tools", CelPolicyProjectRowMapper::convertMetadataTools, metadataBuilder::setTools);
        maybeSet(rs, "inactive_since", CelPolicyProjectRowMapper::convertInactiveSince, builder::setIsActive);
        maybeSet(rs, "bom_generated", RowMapperUtil::nullableTimestamp, metadataBuilder::setBomGenerated);
        builder.setMetadata(metadataBuilder.build());

        return builder.build();
    }

    private static Boolean convertInactiveSince(ResultSet rs, String columnName) throws SQLException {
        return rs.getTimestamp(columnName) == null;
    }

    private static Tools convertMetadataTools(ResultSet rs, String columnName) throws SQLException {
        final String jsonString = rs.getString(columnName);
        if (isBlank(jsonString)) {
            return Tools.getDefaultInstance();
        }

        final org.dependencytrack.model.Tools modelTools;
        try {
            modelTools = Mappers.jsonMapper().readValue(jsonString, org.dependencytrack.model.Tools.class);
        } catch (IOException e) {
            throw new UnableToProduceResultException(e);
        }

        if (modelTools == null) {
            return Tools.getDefaultInstance();
        }

        final var toolsBuilder = Tools.newBuilder();
        if (modelTools.components() != null) {
            modelTools.components().stream()
                    .map(PolicyProtoMapper::mapToProto)
                    .forEach(toolsBuilder::addComponents);
        }

        return toolsBuilder.build();
    }

    private static List<Project.Property> maybeConvertProperties(final ResultSet rs, final String columnName) throws SQLException {
        final String jsonString = rs.getString(columnName);
        if (isBlank(jsonString)) {
            return Collections.emptyList();
        }

        // Protobuf's JsonFormat.Parser can't deserialize JSON arrays.
        // We can't use Jackson's ObjectMapper to deserialize directly to Protobuf objects.
        // Instead, use Jackson's streaming API to iterate over the array, and deserialize individual objects.
        final var properties = new ArrayList<Project.Property>();
        try (final JsonParser jsonParser = Mappers.jsonMapper().createParser(jsonString)) {
            if (jsonParser.nextToken() != JsonToken.START_ARRAY) {
                return Collections.emptyList();
            }

            while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
                if (jsonParser.currentToken() == JsonToken.START_OBJECT) {
                    final JsonNode objectNode = jsonParser.readValueAsTree();
                    final var builder = Project.Property.newBuilder();
                    PROPERTY_JSON_PARSER.merge(objectNode.toString(), builder);
                    properties.add(builder.build());
                } else {
                    jsonParser.skipChildren();
                }
            }
        } catch (IOException e) {
            throw new UnableToProduceResultException(e);
        }
        return properties;
    }

}
