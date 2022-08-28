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