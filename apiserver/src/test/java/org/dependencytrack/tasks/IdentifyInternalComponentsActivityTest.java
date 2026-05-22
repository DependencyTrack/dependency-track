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
package org.dependencytrack.tasks;

import alpine.model.IConfigProperty.PropertyType;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.jdo.Query;
import javax.jdo.Transaction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class IdentifyInternalComponentsActivityTest extends PersistenceCapableTest {

    @BeforeEach
    public void before() throws Exception {
        super.before();

        // Configure internal components to be identified by group "org.acme"
        // and names starting with "foobar-".
        qm.createConfigProperty(ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX.getGroupName(),
                ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX.getPropertyName(),
                "^org\\.acme$", PropertyType.STRING, null);
        qm.createConfigProperty(ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX.getGroupName(),
                ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX.getPropertyName(),
                "^foobar-.*", PropertyType.STRING, null);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        // Batch insert 8 components, 3 of which are supposed to be identified as internal
        final Transaction trx = qm.getPersistenceManager().currentTransaction();
        trx.begin();
        for (int j = 0; j < 5; j++) {
            createComponent("com.example", "example-lib-" + j, project);
        }
        createComponent("org.acme", "acme-lib", project); // Only group matches
        createComponent("com.example", "foobar-baz", project); // Only name matches
        createComponent("org.acme", "foobar-baz", project); // Group and name match
        qm.getPersistenceManager().flush();
        trx.commit();
    }

    @Test
    void shouldFlagComponentsMatchingGroupAndName() throws Exception {
        new IdentifyInternalComponentsActivity().execute(mock(ActivityContext.class), null);
        assertThat(getInternalComponentCount()).isEqualTo(3);
    }

    private void createComponent(final String group, final String name, final Project project) {
        final var component = new Component();
        component.setGroup(group);
        component.setName(name);
        component.setProject(project);
        qm.getPersistenceManager().makePersistent(component);
    }

    private long getInternalComponentCount() throws Exception {
        try (final Query<Component> query = qm.getPersistenceManager().newQuery(Component.class)) {
            query.setFilter("internal == true");
            query.setResult("count(this)");
            return query.executeResultUnique(Long.class);
        }
    }

}
