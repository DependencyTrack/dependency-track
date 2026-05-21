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

import alpine.persistence.AlpineQueryManager;
import jakarta.ws.rs.ext.Provider;
import org.glassfish.jersey.server.monitoring.ApplicationEvent;
import org.glassfish.jersey.server.monitoring.ApplicationEventListener;
import org.glassfish.jersey.server.monitoring.RequestEvent;
import org.glassfish.jersey.server.monitoring.RequestEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jdo.PersistenceManager;
import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

@Provider
public class SessionUsageTracker implements ApplicationEventListener {

    private record SessionUsedEvent(String tokenHash, long timestamp) {
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(SessionUsageTracker.class);
    static final BlockingQueue<SessionUsedEvent> EVENT_QUEUE = new ArrayBlockingQueue<>(10_000);

    private final ScheduledExecutorService flushExecutor;
    private final Lock flushLock;

    public SessionUsageTracker() {
        this.flushExecutor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name("Alpine-SessionUsageTracker")
                        .uncaughtExceptionHandler((thread, throwable) ->
                                LOGGER.error("Uncaught exception in thread {}", thread.getName(), throwable))
                        .factory());
        this.flushLock = new ReentrantLock();
    }

    @Override
    public void onEvent(ApplicationEvent event) {
        switch (event.getType()) {
            case INITIALIZATION_FINISHED -> flushExecutor.scheduleAtFixedRate(this::flush, 5, 30, TimeUnit.SECONDS);
            case DESTROY_FINISHED -> {
                flushExecutor.shutdown();
                try {
                    final boolean terminated = flushExecutor.awaitTermination(5, TimeUnit.SECONDS);
                    if (!terminated) {
                        LOGGER.warn("""
                                Flush executor did not terminate on time (waited for 5s); \
                                Remaining events in the queue: %d""".formatted(EVENT_QUEUE.size()));
                    }
                } catch (InterruptedException e) {
                    LOGGER.warn("Interrupted while waiting for pending flush tasks to complete");
                    Thread.currentThread().interrupt();
                }

                flush();
            }
        }
    }

    @Override
    public RequestEventListener onRequest(RequestEvent requestEvent) {
        return null;
    }

    static void onSessionUsed(String tokenHash) {
        final var event = new SessionUsedEvent(tokenHash, Instant.now().toEpochMilli());
        if (!EVENT_QUEUE.offer(event)) {
            LOGGER.debug("Usage of session can not be tracked because the event queue is already saturated");
        }
    }

    void flush() {
        try {
            flushLock.lock();
            if (EVENT_QUEUE.isEmpty()) {
                return;
            }

            final var lastUsedByHash = new HashMap<String, Long>();
            while (EVENT_QUEUE.peek() != null) {
                final SessionUsedEvent event = EVENT_QUEUE.poll();
                lastUsedByHash.compute(event.tokenHash(), (_, prev) -> {
                    if (prev == null) {
                        return event.timestamp();
                    }

                    return Math.max(prev, event.timestamp());
                });
            }

            LOGGER.debug("Updating last used timestamps for %d sessions".formatted(lastUsedByHash.size()));
            updateLastUsed(lastUsedByHash);
        } catch (Exception e) {
            LOGGER.error("Failed to update last used timestamps of sessions", e);
        } finally {
            flushLock.unlock();
        }
    }

    private void updateLastUsed(Map<String, Long> lastUsedByHash) throws SQLException {
        try (final var qm = new AlpineQueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            final JDOConnection jdoConnection = pm.getDataStoreConnection();
            final var connection = (Connection) jdoConnection.getNativeConnection();

            final var tokenHashes = new String[lastUsedByHash.size()];
            final var lastUsedAts = new Timestamp[lastUsedByHash.size()];

            int i = 0;
            for (final var entry : lastUsedByHash.entrySet()) {
                final String tokenHash = entry.getKey();
                final Long lastUsedEpochMillis = entry.getValue();

                tokenHashes[i] = tokenHash;
                lastUsedAts[i] = new Timestamp(lastUsedEpochMillis);
                i++;
            }

            try (final PreparedStatement ps = connection.prepareStatement("""
                    UPDATE "USER_SESSION"
                       SET "LAST_USED_AT" = t.last_used_at
                      FROM UNNEST(?, ?)
                        AS t(token_hash, last_used_at)
                     WHERE "TOKEN_HASH" = t.token_hash
                       AND ("LAST_USED_AT" IS NULL OR "LAST_USED_AT" < t.last_used_at)
                    """)) {
                ps.setArray(1, connection.createArrayOf("TEXT", tokenHashes));
                ps.setArray(2, connection.createArrayOf("TIMESTAMPTZ", lastUsedAts));
                ps.executeUpdate();
            } finally {
                jdoConnection.close();
            }
        }
    }

}
