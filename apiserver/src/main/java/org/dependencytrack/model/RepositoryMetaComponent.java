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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.jspecify.annotations.Nullable;

import java.util.Date;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class RepositoryMetaComponent {

    private RepositoryType repositoryType;
    private String namespace;
    private String name;
    private String latestVersion;
    private Date lastCheck;
    @Schema(type = "integer", format = "int64", description = "UNIX epoch timestamp in milliseconds")
    private Date latestVersionPublishedAt;

    public static @Nullable RepositoryMetaComponent of(PackageMetadata packageMetadata) {
        if (packageMetadata == null) {
            return null;
        }

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.repositoryType = RepositoryType.resolve(packageMetadata.purl());
        metaComponent.namespace = packageMetadata.purl().getNamespace();
        metaComponent.name = packageMetadata.purl().getName();
        metaComponent.latestVersion = packageMetadata.latestVersion();
        metaComponent.lastCheck = Date.from(packageMetadata.resolvedAt());
        metaComponent.latestVersionPublishedAt = packageMetadata.latestVersionPublishedAt() != null
            ? Date.from(packageMetadata.latestVersionPublishedAt())
            : null;
        return metaComponent;
    }

    public RepositoryType getRepositoryType() {
        return repositoryType;
    }

    public void setRepositoryType(RepositoryType repositoryType) {
        this.repositoryType = repositoryType;
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLatestVersion() {
        return latestVersion;
    }

    public void setLatestVersion(String latestVersion) {
        this.latestVersion = latestVersion;
    }

    public Date getLastCheck() {
        return lastCheck;
    }

    public void setLastCheck(Date lastCheck) {
        this.lastCheck = lastCheck;
    }

    public Date getLatestVersionPublishedAt() {
        return latestVersionPublishedAt;
    }
}
