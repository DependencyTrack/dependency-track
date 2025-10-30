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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.TelemetrySubmissionEvent;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.datastore.JDOConnection;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;

import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_LAST_SUBMISSION_DATA;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_SUBMISSION_ENABLED;

/**
 * @since 4.13.0
 */
public class TelemetrySubmissionTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(TelemetrySubmissionTask.class);

    private final String url;
    private final JsonMapper jsonMapper;

    TelemetrySubmissionTask(final String url) {
        this.url = url;
        this.jsonMapper = new JsonMapper();
    }

    public TelemetrySubmissionTask() {
        this("https://metrics.dependencytrack.org");
    }

    @Override
    public void inform(final Event event) {
        if (!(event instanceof TelemetrySubmissionEvent)) {
            return;
        }

        try (final var qm = new QueryManager()) {
            final boolean isSubmissionEnabled = qm.isEnabled(TELEMETRY_SUBMISSION_ENABLED);
            if (!isSubmissionEnabled) {
                LOGGER.debug("Telemetry submission is disabled");
                return;
            }

            if (!isSubmissionDue(qm)) {
                LOGGER.debug("Telemetry data is not yet due for submission");
                return;
            }
        }

        final TelemetryData data;
        try {
            data = collectTelemetryData();
        } catch (RuntimeException e) {
            LOGGER.error("Failed to collect telemetry data", e);
            return;
        }

        try {
            final String serializedData = jsonMapper.writeValueAsString(data);
            final boolean submitted = submit(this.url, serializedData);
            if (submitted) {
                recordSubmission(serializedData);
            }
        } catch (IOException | RuntimeException e) {
            LOGGER.error("Failed to submit telemetry data", e);
        }
    }

    public record TelemetryData(
            @JsonProperty("system_id") String systemId,
            @JsonProperty("dt_version") String applicationVersion,
            @JsonProperty("db_type") String databaseType,
            @JsonProperty("db_version") String databaseVersion) {
    }

    private TelemetryData collectTelemetryData() {
        final DatabaseInfo databaseInfo;
        try {
            databaseInfo = collectDatabaseInfo();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to collect database info", e);
        }

        return new TelemetryData(
                Config.getInstance().getSystemUuid(),
                Config.getInstance().getApplicationVersion(),
                databaseInfo.productName(),
                databaseInfo.productVersion());
    }

    private record DatabaseInfo(
            String productName,
            String productVersion) {
    }

    private DatabaseInfo collectDatabaseInfo() throws SQLException {
        try (final var qm = new QueryManager()) {
            final JDOConnection jdoConnection = qm.getPersistenceManager().getDataStoreConnection();
            final var nativeConnection = (Connection) jdoConnection.getNativeConnection();
            try {
                final DatabaseMetaData databaseMetaData = nativeConnection.getMetaData();
                return new DatabaseInfo(
                        databaseMetaData.getDatabaseProductName(),
                        databaseMetaData.getDatabaseProductVersion());
            } finally {
                jdoConnection.close();
            }
        }
    }

    private boolean submit(final String url, final String serializedData) throws IOException {
        LOGGER.debug("Submitting %s to %s".formatted(serializedData, url));

        final var request = new HttpPost(url);
        request.setHeader("Content-Type", "application/json");
        request.setHeader("User-Agent", ManagedHttpClientFactory.getUserAgent());
        request.setEntity(new StringEntity(serializedData, StandardCharsets.UTF_8));

        try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            final int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == 429) {
                // This is fine since the task is scheduled to run every hour,
                // implicitly providing a convenient retry mechanism.
                LOGGER.debug("Rate limiting detected, will try to submit upon next task invocation");
                return false;
            } else if (response.getStatusLine().getStatusCode() != 200) {
                // NB: Redirects are handled transparently by the HTTP client
                // for 307 and 308 status codes.
                throw new IllegalStateException(
                        "Received unexpected response code: " + response.getStatusLine().getStatusCode());
            }
        }

        return true;
    }

    private boolean isSubmissionDue(final QueryManager qm) {
        final ConfigProperty lastSubmissionProperty = qm.getConfigProperty(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName());
        if (lastSubmissionProperty == null || lastSubmissionProperty.getPropertyValue() == null) {
            // Telemetry data was never submitted before.
            return true;
        }

        final long lastSubmissionEpochSeconds = Long.parseLong(lastSubmissionProperty.getPropertyValue());
        final var lastSubmission = Instant.ofEpochSecond(lastSubmissionEpochSeconds);

        final Duration durationSinceLastSubmission = Duration.between(lastSubmission, Instant.now());
        return durationSinceLastSubmission.compareTo(Duration.ofDays(1)) > 0;
    }

    private void recordSubmission(final String serializedData) {
        try (final var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                final ConfigProperty lastSubmissionTimestampProperty = qm.getConfigProperty(
                        TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                        TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName());
                if (lastSubmissionTimestampProperty == null) {
                    qm.createConfigProperty(
                            TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getGroupName(),
                            TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyName(),
                            String.valueOf(Instant.now().getEpochSecond()),
                            TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getPropertyType(),
                            TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS.getDescription());
                } else {
                    lastSubmissionTimestampProperty.setPropertyValue(String.valueOf(Instant.now().getEpochSecond()));
                }

                final ConfigProperty lastSubmissionDataProperty = qm.getConfigProperty(
                        TELEMETRY_LAST_SUBMISSION_DATA.getGroupName(),
                        TELEMETRY_LAST_SUBMISSION_DATA.getPropertyName());
                if (lastSubmissionDataProperty == null) {
                    qm.createConfigProperty(
                            TELEMETRY_LAST_SUBMISSION_DATA.getGroupName(),
                            TELEMETRY_LAST_SUBMISSION_DATA.getPropertyName(),
                            serializedData,
                            TELEMETRY_LAST_SUBMISSION_DATA.getPropertyType(),
                            TELEMETRY_LAST_SUBMISSION_DATA.getDescription());
                } else {
                    lastSubmissionDataProperty.setPropertyValue(serializedData);
                }
            });
        }
    }

}
