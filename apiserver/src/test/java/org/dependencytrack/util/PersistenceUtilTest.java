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
package org.dependencytrack.util;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.jdo.PersistenceManager;
import javax.jdo.Transaction;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.util.PersistenceUtil.assertNonPersistent;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

public class PersistenceUtilTest extends PersistenceCapableTest {

    private PersistenceManager pm;

    @BeforeEach
    public void setUp() {
        pm = qm.getPersistenceManager();
    }

    @Test
    public void testAssertPersistentTx() {
        final Transaction trx = pm.currentTransaction();
        try {
            trx.begin();

            final var project = new Project();
            project.setName("foo");
            pm.makePersistent(project);

            assertThatNoException().isThrownBy(() -> assertPersistent(project, null));
        } finally {
            trx.rollback();
        }
    }

    @Test
    public void testAssertPersistentNonTx() {
        final var project = new Project();
        project.setName("foo");
        pm.makePersistent(project);

        assertThatNoException().isThrownBy(() -> assertPersistent(project, null));
    }

    @Test
    public void testAssertPersistentWhenTransient() {
        final var project = new Project();
        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> assertPersistent(project, null));
    }

    @Test
    public void testAssertPersistentWhenDetached() {
        final var project = new Project();
        project.setName("foo");
        pm.makePersistent(project);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> assertPersistent(pm.detachCopy(project), null));
    }

    @Test
    public void testAssertNonPersistentTx() {
        final Transaction trx = pm.currentTransaction();
        try {
            trx.begin();

            final var project = new Project();
            project.setName("foo");
            pm.makePersistent(project);

            assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> assertNonPersistent(project, null));
        } finally {
            trx.rollback();
        }
    }

    @Test
    public void testAssertNonPersistentNonTx() {
        final var project = new Project();
        project.setName("foo");
        pm.makePersistent(project);

        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> assertNonPersistent(project, null));
    }

    @Test
    public void testAssertNonPersistentWhenTransient() {
        final var project = new Project();
        assertThatNoException().isThrownBy(() -> assertNonPersistent(project, null));
    }

    @Test
    public void testAssertNonPersistentWhenDetached() {
        final var project = new Project();
        project.setName("foo");
        pm.makePersistent(project);

        assertThatNoException().isThrownBy(() -> assertNonPersistent(pm.detachCopy(project), null));
    }
}
