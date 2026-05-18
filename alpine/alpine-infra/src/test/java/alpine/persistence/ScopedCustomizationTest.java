/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.persistence;

import org.datanucleus.api.jdo.JDOPersistenceManager;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.jdo.JDOHelper;

import static javax.jdo.FetchPlan.DETACH_LOAD_FIELDS;
import static javax.jdo.FetchPlan.DETACH_UNLOAD_FIELDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.datanucleus.PropertyNames.PROPERTY_DETACH_ALL_ON_COMMIT;

public class ScopedCustomizationTest {

    private JDOPersistenceManagerFactory pmf;
    private JDOPersistenceManager pm;

    @BeforeEach
    public void setUp() {
        pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(JdoProperties.unit(), "Alpine");
        pm = (JDOPersistenceManager) pmf.getPersistenceManager();
    }

    @AfterEach
    public void tearDown() {
        if (pm != null) {
            pm.close();
        }

        if (pmf != null) {
            pmf.close();
        }
    }

    @Test
    public void testRestoreDetachmentOptions() {
        pm.getFetchPlan().setDetachmentOptions(DETACH_LOAD_FIELDS);
        assertThat(pm.getFetchPlan().getDetachmentOptions()).isEqualTo(DETACH_LOAD_FIELDS);

        try (var _ = new ScopedCustomization(pm).withDetachmentOptions(DETACH_UNLOAD_FIELDS)) {
            assertThat(pm.getFetchPlan().getDetachmentOptions()).isEqualTo(DETACH_UNLOAD_FIELDS);
        }

        assertThat(pm.getFetchPlan().getDetachmentOptions()).isEqualTo(DETACH_LOAD_FIELDS);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testRestoreFetchGroups() {
        pm.getFetchPlan().setGroups("foo");
        assertThat(pm.getFetchPlan().getGroups()).containsOnly("foo");

        try (var _ = new ScopedCustomization(pm).withFetchGroup("bar")) {
            assertThat(pm.getFetchPlan().getGroups()).containsOnly("bar");
        }

        assertThat(pm.getFetchPlan().getGroups()).containsOnly("foo");
    }

    @Test
    public void testRestoreProperties() {
        pm.setProperty(PROPERTY_DETACH_ALL_ON_COMMIT, "true");
        assertThat(pm.getExecutionContext().getProperty(PROPERTY_DETACH_ALL_ON_COMMIT)).isEqualTo("true");

        try (var _ = new ScopedCustomization(pm).withProperty(PROPERTY_DETACH_ALL_ON_COMMIT, "false")) {
            assertThat(pm.getExecutionContext().getProperty(PROPERTY_DETACH_ALL_ON_COMMIT)).isEqualTo("false");
        }

        assertThat(pm.getExecutionContext().getProperty(PROPERTY_DETACH_ALL_ON_COMMIT)).isEqualTo("true");
    }

}