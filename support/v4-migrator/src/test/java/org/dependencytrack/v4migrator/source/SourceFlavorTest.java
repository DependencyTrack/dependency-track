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
package org.dependencytrack.v4migrator.source;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SourceFlavorTest {

    @Test
    void detectsPostgresql() {
        assertThat(SourceFlavor.fromJdbcUrl("jdbc:postgresql://host:5432/db"))
            .isEqualTo(SourceFlavor.POSTGRESQL);
    }

    @Test
    void detectsMssql() {
        assertThat(SourceFlavor.fromJdbcUrl("jdbc:sqlserver://host:1433;databaseName=db"))
            .isEqualTo(SourceFlavor.MSSQL);
    }

    @Test
    void rejectsNull() {
        assertThatThrownBy(() -> SourceFlavor.fromJdbcUrl(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("required");
    }

    @Test
    void rejectsUnknownFlavor() {
        assertThatThrownBy(() -> SourceFlavor.fromJdbcUrl("jdbc:mysql://host/db"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unsupported");
    }
}
