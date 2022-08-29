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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.junit.Test;

import javax.jdo.Transaction;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

public class PersistenceUtilTest extends PersistenceCapableTest {

    @Test
    public void testRequireDetachedWithNewObject() {
        assertThatNoException()
                .isThrownBy(() -> PersistenceUtil.requireDetached(new Project()));
    }

    @Test
    public void testRequireDetachedWithTransientObject() {
        final Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        qm.getPersistenceManager().makeTransient(project);
        assertThatNoException()
                .isThrownBy(() -> PersistenceUtil.requireDetached(project));
    }

    @Test
    public void testRequireDetachedWithDetachedObject() {
        final Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        assertThatNoException()
                .isThrownBy(() -> PersistenceUtil.requireDetached(qm.getPersistenceManager().detachCopy(project)));
    }

    @Test
    public void testRequireDetachedWithPersistentObject() {
        final Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> PersistenceUtil.requireDetached(project));
    }

    @Test
    public void testRequireDetachedWithTransactionalObject() {
        final Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);

        final Transaction trx = qm.getPersistenceManager().currentTransaction();
        try {
            trx.begin();
            qm.getPersistenceManager().makeTransactional(project);
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> PersistenceUtil.requireDetached(project));
            trx.commit();
        } finally {
            if (trx.isActive()) {
                trx.rollback();
            }
        }
    }

}