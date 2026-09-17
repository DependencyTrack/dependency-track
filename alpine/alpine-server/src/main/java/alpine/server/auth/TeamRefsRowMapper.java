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
package alpine.server.auth;

import alpine.model.auth.TeamRef;
import alpine.persistence.RowMapper;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@NullMarked
final class TeamRefsRowMapper implements RowMapper<List<TeamRef>> {

    @Override
    public List<TeamRef> map(ResultSet rs) throws SQLException {
        final Long[] ids = getArray(rs, "team_ids");
        if (ids == null) {
            return List.of();
        }

        final String[] names = getArray(rs, "team_names");
        final String[] uuids = getArray(rs, "team_uuids");

        if (names == null || uuids == null || names.length != ids.length || uuids.length != ids.length) {
            throw new SQLException("Team columns are of unequal length");
        }

        final var teams = new ArrayList<TeamRef>(ids.length);
        for (int i = 0; i < ids.length; i++) {
            teams.add(new TeamRef(ids[i], names[i], UUID.fromString(uuids[i])));
        }

        return teams;
    }

    @SuppressWarnings("unchecked")
    private static <T> T @Nullable [] getArray(ResultSet rs, String columnName) throws SQLException {
        final Array array = rs.getArray(columnName);
        if (rs.wasNull()) {
            return null;
        }

        return (T[]) array.getArray();
    }
}
