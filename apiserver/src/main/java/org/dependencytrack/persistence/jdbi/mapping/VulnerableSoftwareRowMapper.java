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
package org.dependencytrack.persistence.jdbi.mapping;

import com.fasterxml.jackson.core.type.TypeReference;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.VulnerableSoftware;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.deserializeJson;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

/**
 * @since 5.0.0
 */
public class VulnerableSoftwareRowMapper implements RowMapper<VulnerableSoftware> {

    private static final TypeReference<List<AffectedVersionAttribution>> ATTRIBUTIONS_TYPE_REF = new TypeReference<>() {
    };

    private final RowMapper<VulnerableSoftware> vulnerableSoftwareMapper = BeanMapper.of(VulnerableSoftware.class);

    @Override
    public VulnerableSoftware map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final VulnerableSoftware vs = vulnerableSoftwareMapper.map(rs, ctx);
        maybeSet(rs, "attributionsJson",
                (ignored, columnName) -> deserializeJson(rs, columnName, ATTRIBUTIONS_TYPE_REF),
                vs::setAffectedVersionAttributions);
        return vs;
    }

}
