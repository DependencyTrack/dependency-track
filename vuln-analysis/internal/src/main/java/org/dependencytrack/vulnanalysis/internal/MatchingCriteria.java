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
package org.dependencytrack.vulnanalysis.internal;

import com.github.packageurl.PackageURL;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
record MatchingCriteria(
        long vulnDbId,
        String vulnId,
        String vulnSource,
        @Nullable String cpe23,
        @Nullable String cpePart,
        @Nullable String cpeVendor,
        @Nullable String cpeProduct,
        @Nullable String version,
        @Nullable String cpeUpdate,
        @Nullable String cpeEdition,
        @Nullable String cpeLanguage,
        @Nullable String cpeSwEdition,
        @Nullable String cpeTargetSw,
        @Nullable String cpeTargetHw,
        @Nullable String cpeOther,
        @Nullable PackageURL purl,
        @Nullable String purlType,
        @Nullable String purlNamespace,
        @Nullable String purlName,
        @Nullable String versionEndExcluding,
        @Nullable String versionEndIncluding,
        @Nullable String versionStartExcluding,
        @Nullable String versionStartIncluding,
        int coordinateIndex) {

    boolean hasRange() {
        return versionEndExcluding != null
                || versionEndIncluding != null
                || versionStartExcluding != null
                || versionStartIncluding != null;
    }

    static class RowMapper implements org.jdbi.v3.core.mapper.RowMapper<MatchingCriteria> {

        private @Nullable ColumnMapper<PackageURL> purlColumnMapper;

        @Override
        public void init(ConfigRegistry registry) {
            purlColumnMapper = registry.get(ColumnMappers.class).findFor(PackageURL.class).orElseThrow();
        }

        @Override
        public MatchingCriteria map(ResultSet rs, StatementContext ctx) throws SQLException {
            requireNonNull(purlColumnMapper);

            return new MatchingCriteria(
                    rs.getLong("vuln_db_id"),
                    rs.getString("vuln_id"),
                    rs.getString("vuln_source"),
                    rs.getString("cpe23"),
                    rs.getString("part"),
                    rs.getString("vendor"),
                    rs.getString("product"),
                    rs.getString("version"),
                    rs.getString("update"),
                    rs.getString("edition"),
                    rs.getString("language"),
                    rs.getString("swedition"),
                    rs.getString("targetsw"),
                    rs.getString("targethw"),
                    rs.getString("other"),
                    purlColumnMapper.map(rs, rs.findColumn("purl"), ctx),
                    rs.getString("purl_type"),
                    rs.getString("purl_namespace"),
                    rs.getString("purl_name"),
                    rs.getString("versionendexcluding"),
                    rs.getString("versionendincluding"),
                    rs.getString("versionstartexcluding"),
                    rs.getString("versionstartincluding"),
                    rs.getInt("coordinate_index"));
        }

    }

}
