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
package org.dependencytrack.v4migrator.extract;

import org.dependencytrack.v4migrator.TableMigration;
import org.dependencytrack.v4migrator.config.SourceOptions;
import org.dependencytrack.v4migrator.source.SourceFlavor;
import org.jdbi.v3.core.Jdbi;

/**
 * Source-flavor strategy for extracting v4 rows into {@code <staging>.src_<TABLE>}.
 */
public interface SourceExtractor {

    /**
     * Pull rows for {@code table} from the v4 source and write them into the staging
     * source-typed table. Both source and target connections are opened by the implementation.
     *
     * @return the number of rows extracted.
     */
    long extract(TableMigration table, String stagingSchema, Jdbi target, long sampleLimit) throws Exception;

    static SourceExtractor forSource(final SourceOptions source) {
        final SourceFlavor flavor = SourceFlavor.fromJdbcUrl(source.sourceUrl);
        return switch (flavor) {
            case POSTGRESQL -> new PostgresExtractor(source);
            case MSSQL -> new MssqlExtractor(source);
        };
    }
}
