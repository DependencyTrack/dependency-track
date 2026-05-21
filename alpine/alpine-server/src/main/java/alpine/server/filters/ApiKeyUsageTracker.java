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
package alpine.server.filters;

import alpine.model.ApiKey;
import alpine.persistence.AlpineQueryManager;
import jakarta.ws.rs.ext.Provider;
import org.glassfish.jersey.server.monitoring.ApplicationEvent;
import org.glassfish.jersey.server.monitoring.ApplicationEventListener;
import org.glassfish.jersey.server.monitoring.RequestEvent;
import org.glassfish.jersey.server.monitoring.RequestEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
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
public class ApiKeyUsageTracker implements ApplicationEventListener {

    private record ApiKeyUsedEvent(long keyId, long timestamp) {
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiKeyUsageTracker.class);
    private static final BlockingQueue<ApiKeyUsedEvent> EVENT_QUEUE = new ArrayBlockingQueue<>(10_000);

    private final ScheduledExecutorService flushExecutor;
    private final Lock flushLock;

    public ApiKeyUsageTracker() {
        this.flushExecutor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .uncaughtExceptionHandler((thread, throwable) ->
                                LOGGER.error("Uncaught exception in thread {}", thread.getName(), throwable))
                        .name("Alpine-ApiKeyUsageTracker")
                        .factory());
        this.flushLock = new ReentrantLock();
    }

    @Override
    public void onEvent(final ApplicationEvent event) {
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
    public RequestEventListener onRequest(final RequestEvent requestEvent) {
        return null;
    }

    static void onApiKeyUsed(final ApiKey apiKey) {
        final var event = new ApiKeyUsedEvent(apiKey.getId(), Instant.now().toEpochMilli());
        if (!EVENT_QUEUE.offer(event)) {
            // Prefer lost events over blocking when the queue is saturated.
            // We do not want to add additional latency to requests.
            LOGGER.debug("Usage of API key %s can not be tracked because the event queue is already saturated"
                    .formatted(apiKey.getMaskedKey()));
        }
    }

    private void flush() {
        try {
            flushLock.lock();
            if (EVENT_QUEUE.isEmpty()) {
                return;
            }

            final var lastUsedByKeyId = new HashMap<Long, Long>();
            while (EVENT_QUEUE.peek() != null) {
                final ApiKeyUsedEvent event = EVENT_QUEUE.poll();
                lastUsedByKeyId.compute(event.keyId(), (_, prev) -> {
                    if (prev == null) {
                        return event.timestamp();
                    }

                    return Math.max(prev, event.timestamp());
                });
            }

            LOGGER.debug("Updating last used timestamps for %d API keys".formatted(lastUsedByKeyId.size()));
            updateLastUsed(lastUsedByKeyId);
        } catch (Exception e) {
            LOGGER.error("Failed to update last used timestamps of API keys", e);
        } finally {
            flushLock.unlock();
        }
    }

    private void updateLastUsed(final Map<Long, Long> lastUsedByKeyId) throws SQLException {
        try (final var qm = new AlpineQueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            final JDOConnection jdoConnection = pm.getDataStoreConnection();
            final var connection = (Connection) jdoConnection.getNativeConnection();
            try (final PreparedStatement ps = connection.prepareStatement("""
                    UPDATE "APIKEY" SET "LAST_USED" = ?
                    WHERE "ID" = ? AND ("LAST_USED" IS NULL OR "LAST_USED" < ?)
                    """)) {
                for (final Map.Entry<Long, Long> entry : lastUsedByKeyId.entrySet()) {
                    final var lastUsed = new Timestamp(entry.getValue());
                    ps.setTimestamp(1, lastUsed);
                    ps.setLong(2, entry.getKey());
                    ps.setTimestamp(3, lastUsed);
                    ps.addBatch();
                }

                ps.executeBatch();
            } finally {
                jdoConnection.close();
            }

            // Evict ApiKey objects from L2 cache.
            // DataNucleus does the same when using the bulk UPDATE feature ¯\_(ツ)_/¯
            final PersistenceManagerFactory pmf = pm.getPersistenceManagerFactory();
            pmf.getDataStoreCache().evictAll(false, ApiKey.class);
        }
    }

}
