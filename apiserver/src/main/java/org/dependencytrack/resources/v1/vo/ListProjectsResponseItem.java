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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.packageurl.PackageURL;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.jdbi.ProjectDao.ListProjectsRow;
import org.dependencytrack.resources.v1.serializers.CustomPackageURLSerializer;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/// @since 5.0.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ListProjectsResponseItem(
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) UUID uuid,
        @Nullable String group,
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED) String name,
        @Nullable String version,
        @Nullable Classifier classifier,
        @Nullable String description,
        @Nullable String publisher,
        @Schema(type = "string")
        @Nullable @JsonSerialize(using = CustomPackageURLSerializer.class) PackageURL purl,
        @Nullable String swidTagId,
        @Nullable String cpe,
        @Nullable String directDependencies,
        @JsonProperty("isLatest") boolean isLatest,
        @Schema(accessMode = Schema.AccessMode.READ_ONLY)
        @Nullable Date inactiveSince,
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
        @Nullable Date lastBomImport,
        @Nullable String lastBomImportFormat,
        @Nullable Date lastVulnerabilityAnalysis,
        @Nullable Double lastInheritedRiskScore,
        @Nullable List<ExternalReference> externalReferences,
        @Nullable OrganizationalEntity supplier,
        @Nullable OrganizationalEntity manufacturer,
        @Nullable List<OrganizationalContact> authors,
        @Nullable Collection<Tag> tags,
        @Nullable ProjectMetadata metadata,
        @Nullable ProjectMetrics metrics,
        @Nullable ProjectCollectionLogic collectionLogic,
        @Nullable Tag collectionTag,
        @Nullable Parent parent,
        @Schema(description = "Whether the project has child projects", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean hasChildren) {

    public static List<ListProjectsResponseItem> of(Collection<ListProjectsRow> rows) {
        return rows.stream()
                .map(ListProjectsResponseItem::of)
                .toList();
    }

    public static ListProjectsResponseItem of(ListProjectsRow row) {
        return new ListProjectsResponseItem(
                row.uuid(),
                row.group(),
                row.name(),
                row.version(),
                row.classifier(),
                row.description(),
                row.publisher(),
                row.purl(),
                row.swidTagId(),
                row.cpe(),
                row.directDependencies(),
                row.isLatest(),
                row.inactiveSince(),
                row.lastBomImport(),
                row.lastBomImportFormat(),
                row.lastVulnerabilityAnalysis(),
                row.lastInheritedRiskScore(),
                row.externalReferences(),
                row.supplier(),
                row.manufacturer(),
                row.authors(),
                row.tagNames() != null && !row.tagNames().isEmpty()
                        ? row.tagNames().stream().map(Tag::new).toList()
                        : null,
                row.metadata(),
                row.metrics(),
                row.collectionLogic(),
                row.collectionTagName() != null
                        ? new Tag(row.collectionTagName())
                        : null,
                Parent.of(row.parentUuid(), row.parentName(), row.parentVersion()),
                row.hasChildren());
    }

    public boolean isActive() {
        return inactiveSince == null;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Parent(
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) UUID uuid,
            @Schema(requiredMode = Schema.RequiredMode.REQUIRED) String name,
            @Nullable String version) {

        private static @Nullable Parent of(
                @Nullable UUID uuid,
                @Nullable String name,
                @Nullable String version) {
            if (uuid == null) {
                return null;
            }

            return new Parent(uuid, name, version);
        }

    }

}
