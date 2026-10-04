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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

class ConfigPropertyDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private ConfigPropertyDao dao;

    @BeforeEach
    void beforeEach() {
        jdbiHandle = openJdbiHandle();
        dao = jdbiHandle.attach(ConfigPropertyDao.class);
    }

    @AfterEach
    void afterEach() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
    }

    @ParameterizedTest
    @CsvSource({"GENERAL_BADGE_ENABLED, true, true", "VULNERABILITY_SOURCE_EPSS_ENABLED, false, false"})
    void isEnabledShouldReturnStoredValue(
            ConfigPropertyConstants property, String storedValue, boolean expectedEnabled) {
        qm.createConfigProperty(
                property.getGroupName(), property.getPropertyName(), storedValue, property.getPropertyType(), null);

        assertThat(dao.isEnabled(property)).isEqualTo(expectedEnabled);
    }

    @ParameterizedTest
    @CsvSource({"GENERAL_BADGE_ENABLED, false", "VULNERABILITY_SOURCE_EPSS_ENABLED, true"})
    void isEnabledShouldFallBackToDefaultWhenPropertyIsMissing(
            ConfigPropertyConstants property, boolean expectedEnabled) {
        assertThat(dao.isEnabled(property)).isEqualTo(expectedEnabled);
    }
}
