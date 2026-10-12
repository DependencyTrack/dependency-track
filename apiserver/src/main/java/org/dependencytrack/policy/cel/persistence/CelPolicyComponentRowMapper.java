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

import org.dependencytrack.persistence.jdbi.mapping.OptionalColumnRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil;
import org.dependencytrack.proto.policy.v1.Component;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.NullMarked;

import java.sql.ResultSet;
import java.sql.SQLException;

@NullMarked
public final class CelPolicyComponentRowMapper implements OptionalColumnRowMapper<Component> {

    @Override
    public Component map(ResultSet rs, StatementContext ctx, Columns columns) throws SQLException {
        final var builder = Component.newBuilder();
        columns.maybeSet(rs, "uuid", ResultSet::getString, builder::setUuid);
        columns.maybeSet(rs, "group", ResultSet::getString, builder::setGroup);
        columns.maybeSet(rs, "name", ResultSet::getString, builder::setName);
        columns.maybeSet(rs, "version", ResultSet::getString, builder::setVersion);
        columns.maybeSet(rs, "scope", ResultSet::getString, builder::setScope);
        columns.maybeSet(rs, "classifier", ResultSet::getString, builder::setClassifier);
        columns.maybeSet(rs, "cpe", ResultSet::getString, builder::setCpe);
        columns.maybeSet(rs, "purl", ResultSet::getString, builder::setPurl);
        columns.maybeSet(rs, "swid_tag_id", ResultSet::getString, builder::setSwidTagId);
        columns.maybeSet(rs, "is_internal", ResultSet::getBoolean, builder::setIsInternal);
        columns.maybeSet(rs, "md5", ResultSet::getString, builder::setMd5);
        columns.maybeSet(rs, "sha1", ResultSet::getString, builder::setSha1);
        columns.maybeSet(rs, "sha256", ResultSet::getString, builder::setSha256);
        columns.maybeSet(rs, "sha384", ResultSet::getString, builder::setSha384);
        columns.maybeSet(rs, "sha512", ResultSet::getString, builder::setSha512);
        columns.maybeSet(rs, "sha3_256", ResultSet::getString, builder::setSha3256);
        columns.maybeSet(rs, "sha3_384", ResultSet::getString, builder::setSha3384);
        columns.maybeSet(rs, "sha3_512", ResultSet::getString, builder::setSha3512);
        columns.maybeSet(rs, "blake2b_256", ResultSet::getString, builder::setBlake2B256);
        columns.maybeSet(rs, "blake2b_384", ResultSet::getString, builder::setBlake2B384);
        columns.maybeSet(rs, "blake2b_512", ResultSet::getString, builder::setBlake2B512);
        columns.maybeSet(rs, "blake3", ResultSet::getString, builder::setBlake3);
        columns.maybeSet(rs, "streebog_256", ResultSet::getString, builder::setStreebog256);
        columns.maybeSet(rs, "streebog_512", ResultSet::getString, builder::setStreebog512);
        columns.maybeSet(rs, "license_name", ResultSet::getString, builder::setLicenseName);
        columns.maybeSet(rs, "license_expression", ResultSet::getString, builder::setLicenseExpression);
        columns.maybeSet(rs, "published_at", RowMapperUtil::nullableTimestamp, builder::setPublishedAt);
        columns.maybeSet(rs, "latest_version", ResultSet::getString, builder::setLatestVersion);
        columns.maybeSet(
                rs,
                "latest_version_published_at",
                RowMapperUtil::nullableTimestamp,
                builder::setLatestVersionPublishedAt);
        columns.maybeSet(rs, "package_artifact_md5", ResultSet::getString, builder::setPackageArtifactMd5);
        columns.maybeSet(rs, "package_artifact_sha1", ResultSet::getString, builder::setPackageArtifactSha1);
        columns.maybeSet(rs, "package_artifact_sha256", ResultSet::getString, builder::setPackageArtifactSha256);
        columns.maybeSet(rs, "package_artifact_sha512", ResultSet::getString, builder::setPackageArtifactSha512);
        return builder.build();
    }
}
