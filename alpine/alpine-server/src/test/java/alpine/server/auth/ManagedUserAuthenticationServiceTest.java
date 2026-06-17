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
package alpine.server.auth;

import alpine.persistence.AlpineQueryManager;
import alpine.server.persistence.PersistenceManagerFactory;
import org.assertj.core.api.SoftAssertionsProvider.ThrowingRunnable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class ManagedUserAuthenticationServiceTest {

    @AfterEach
    public void tearDown() {
        PersistenceManagerFactory.tearDown();
    }

    @Test
    @Disabled("Flaky")
    void shouldNotAllowForUserEnumerationViaTimingAttacks() {
        try (final var qm = new AlpineQueryManager()) {
            final char[] passwordHash = PasswordService.createHash("tset".toCharArray());
            qm.createManagedUser("test", String.valueOf(passwordHash));
        }

        var authService = new ManagedUserAuthenticationService("test", "foo");
        final Duration existingUserWrongPasswordDuration = runTimed(authService::authenticate);

        authService = new ManagedUserAuthenticationService("test", "tset");
        final Duration existingUserCorrectPasswordDuration = runTimed(authService::authenticate);

        authService = new ManagedUserAuthenticationService("doesNotExist", "doesNotMatter");
        final Duration nonExistingUserDuration = runTimed(authService::authenticate);

        // Asserting on timings is the only way to verify that the authentication mechanism
        // is not vulnerable to timing attacks. This is extremely brittle, however, as timings
        // can be influenced by other processes, resource contention, and JVM behavior.
        //
        // There is no way have this test be reliable while still providing meaningful feedback.
        // Even a tolerance of just 200ms is already too much. For this reason, this test is
        // disabled until we find a better way to verify the desired behavior.
        //
        // Manual testing with a fully-fledged application has shown no observable
        // difference between any of the three actions.
        assertThat(nonExistingUserDuration).isCloseTo(existingUserCorrectPasswordDuration, Duration.ofMillis(200));
        assertThat(nonExistingUserDuration).isCloseTo(existingUserWrongPasswordDuration, Duration.ofMillis(200));
    }

    private Duration runTimed(final ThrowingRunnable runnable) {
        final long startTimeNs = System.nanoTime();

        try {
            runnable.run();
        } catch (AlpineAuthenticationException e) {
            // ignored
        } catch (Exception e) {
            Assertions.fail(e);
        }

        return Duration.ofNanos(System.nanoTime() - startTimeNs);
    }

}