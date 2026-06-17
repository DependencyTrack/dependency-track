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
package alpine.server.filters;

import alpine.model.ManagedUser;
import alpine.model.UserSession;
import alpine.persistence.AlpineQueryManager;
import alpine.server.auth.SessionTokenService;
import alpine.server.persistence.PersistenceManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class SessionUsageTrackerTest {

    @AfterEach
    void tearDown() {
        SessionUsageTracker.EVENT_QUEUE.clear();
        PersistenceManagerFactory.tearDown();
    }

    @Test
    void shouldUpdateLastUsedAtOnFlush() throws Exception {
        final String tokenHash;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.createManagedUser("test", "test");
            final String rawToken = new SessionTokenService().createSession(user.getId());
            tokenHash = sha256Hex(rawToken);
        }

        SessionUsageTracker.onSessionUsed(tokenHash);

        final var tracker = new SessionUsageTracker();
        tracker.flush();

        try (final var qm = new AlpineQueryManager()) {
            final var session = qm.getObjectById(UserSession.class, tokenHash);
            assertThat(session.getLastUsedAt()).isNotNull();
        }
    }

    @Test
    void shouldDeduplicateEventsForSameSession() throws Exception {
        final String tokenHash;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.createManagedUser("test", "test");
            final String rawToken = new SessionTokenService().createSession(user.getId());
            tokenHash = sha256Hex(rawToken);
        }

        SessionUsageTracker.onSessionUsed(tokenHash);
        SessionUsageTracker.onSessionUsed(tokenHash);
        SessionUsageTracker.onSessionUsed(tokenHash);

        final var tracker = new SessionUsageTracker();
        tracker.flush();

        try (final var qm = new AlpineQueryManager()) {
            final var session = qm.getObjectById(UserSession.class, tokenHash);
            assertThat(session.getLastUsedAt()).isNotNull();
        }
    }

    @Test
    void shouldHandleMultipleSessions() throws Exception {
        final String tokenHashA;
        final String tokenHashB;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.createManagedUser("test", "test");
            final var service = new SessionTokenService();
            tokenHashA = sha256Hex(service.createSession(user.getId()));
            tokenHashB = sha256Hex(service.createSession(user.getId()));
        }

        SessionUsageTracker.onSessionUsed(tokenHashA);
        SessionUsageTracker.onSessionUsed(tokenHashB);

        final var tracker = new SessionUsageTracker();
        tracker.flush();

        try (final var qm = new AlpineQueryManager()) {
            assertThat(qm.getObjectById(UserSession.class, tokenHashA).getLastUsedAt()).isNotNull();
            assertThat(qm.getObjectById(UserSession.class, tokenHashB).getLastUsedAt()).isNotNull();
        }
    }

    @Test
    void shouldNotDowngradeLastUsedAt() throws Exception {
        final String tokenHash;
        try (final var qm = new AlpineQueryManager()) {
            final ManagedUser user = qm.createManagedUser("test", "test");
            final String rawToken = new SessionTokenService().createSession(user.getId());
            tokenHash = sha256Hex(rawToken);
        }

        final var futureDate = new SimpleDateFormat("yyyy-MM-dd").parse("2099-01-01");
        try (final var qm = new AlpineQueryManager()) {
            final var session = qm.getObjectById(UserSession.class, tokenHash);
            session.setLastUsedAt(futureDate);
        }

        // Queue an event whose timestamp will be earlier than 2099.
        SessionUsageTracker.onSessionUsed(tokenHash);

        final var tracker = new SessionUsageTracker();
        tracker.flush();

        try (final var qm = new AlpineQueryManager()) {
            final var session = qm.getObjectById(UserSession.class, tokenHash);
            assertThat(session.getLastUsedAt()).isEqualTo(futureDate);
        }
    }

    @Test
    void shouldNotFailWhenQueueIsEmpty() {
        final var tracker = new SessionUsageTracker();
        assertThatNoException().isThrownBy(tracker::flush);
    }

    @Test
    void shouldDropEventsWhenQueueIsSaturated() {
        for (int i = 0; i < 10_000; i++) {
            SessionUsageTracker.onSessionUsed("hash-" + i);
        }

        assertThatNoException().isThrownBy(() -> SessionUsageTracker.onSessionUsed("overflow"));
    }

    private static String sha256Hex(String input) throws Exception {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }

}
