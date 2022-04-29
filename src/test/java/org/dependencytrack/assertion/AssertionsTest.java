package org.dependencytrack.assertion;

import org.junit.Test;

import java.time.Duration;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;

public class AssertionsTest {

    @Test
    public void testAssertConditionWithTimeout() {
        assertThatNoException()
                .isThrownBy(() -> assertConditionWithTimeout(new TestSupplier(), Duration.ofMillis(500)));

        assertThatExceptionOfType(AssertionError.class)
                .isThrownBy(() -> assertConditionWithTimeout(() -> false, Duration.ofMillis(200)));
    }

    private static class TestSupplier implements Supplier<Boolean> {

        private static final int FALSE_INVOCATIONS = 2;
        private int invocations;

        @Override
        public Boolean get() {
            return invocations++ >= FALSE_INVOCATIONS;
        }

    }

}
