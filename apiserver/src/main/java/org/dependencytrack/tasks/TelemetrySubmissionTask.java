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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.smallrye.config.SmallRyeConfig;
import org.dependencytrack.common.ClusterInfo;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_LAST_SUBMISSION_DATA;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS;
import static org.dependencytrack.model.ConfigPropertyConstants.TELEMETRY_SUBMISSION_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
public final class TelemetrySubmissionTask implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(TelemetrySubmissionTask.class);
    private static final Duration SUBMISSION_INTERVAL = Duration.ofHours(24);
    private static final String DEFAULT_SUBMISSION_URL = "https://metrics.dependencytrack.org";

    private final HttpClient httpClient;
    private final Config config;
    private final String submissionUrl;

    public TelemetrySubmissionTask(HttpClient httpClient, Config config) {
        this(httpClient, config, DEFAULT_SUBMISSION_URL);
    }

    TelemetrySubmissionTask(HttpClient httpClient, Config config, String submissionUrl) {
        this.httpClient = httpClient;
        this.config = config;
        this.submissionUrl = submissionUrl;
    }

    @Override
    public void run() {
        if (config.unwrap(SmallRyeConfig.class).getProfiles().contains("dev")) {
            LOGGER.debug("Telemetry submission is disabled for dev profile");
            return;
        }

        final String serializedData = collectIfDue();
        if (serializedData == null) {
            return;
        }

        if (!submit(serializedData)) {
            return;
        }

        useJdbiTransaction(handle -> {
            final var dao = handle.attach(ConfigPropertyDao.class);
            final long epochSeconds = Instant.now().getEpochSecond();
            dao.setValue(TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS, String.valueOf(epochSeconds));
            dao.setValue(TELEMETRY_LAST_SUBMISSION_DATA, serializedData);
        });
    }

    private @Nullable String collectIfDue() {
        return withJdbiHandle(handle -> {
            final var dao = handle.attach(ConfigPropertyDao.class);

            if (!dao.getOptionalValue(TELEMETRY_SUBMISSION_ENABLED, Boolean.class).orElse(true)) {
                LOGGER.debug("Telemetry submission is disabled");
                return null;
            }

            if (!isSubmissionDue(dao)) {
                LOGGER.debug("Telemetry submission is not yet due");
                return null;
            }

            final TelemetryData telemetryData;
            try {
                telemetryData = collectTelemetryData(handle.getConnection().getMetaData());
            } catch (SQLException e) {
                LOGGER.warn("Failed to collect database metadata for telemetry", e);
                return null;
            }

            try {
                return Mappers.jsonMapper().writeValueAsString(telemetryData);
            } catch (JsonProcessingException e) {
                LOGGER.warn("Failed to serialize telemetry data", e);
                return null;
            }
        });
    }

    private static boolean isSubmissionDue(ConfigPropertyDao dao) {
        final Optional<Long> lastSubmissionEpochSeconds = dao.getOptionalValue(
                TELEMETRY_LAST_SUBMISSION_EPOCH_SECONDS, Long.class);
        if (lastSubmissionEpochSeconds.isEmpty()) {
            return true;
        }

        final var lastSubmission = Instant.ofEpochSecond(lastSubmissionEpochSeconds.get());
        return Duration.between(lastSubmission, Instant.now()).compareTo(SUBMISSION_INTERVAL) >= 0;
    }

    private TelemetryData collectTelemetryData(DatabaseMetaData dbMetaData) throws SQLException {
        final String systemId = ClusterInfo.getClusterId();
        final String applicationVersion = config
                .getOptionalValue("alpine.build-info.application.version", String.class)
                .orElse("Unknown");
        final String dbType = dbMetaData.getDatabaseProductName();
        final String dbVersion = dbMetaData.getDatabaseProductVersion();

        return new TelemetryData(systemId, applicationVersion, dbType, dbVersion);
    }

    private boolean submit(String serializedData) {
        try {
            final var request = HttpRequest.newBuilder()
                    .uri(URI.create(submissionUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(serializedData))
                    .build();

            final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 429) {
                LOGGER.info("Telemetry endpoint indicated rate limiting; deferring submission");
                return false;
            }

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                LOGGER.info("Telemetry data submitted successfully");
                return true;
            }

            LOGGER.warn("Telemetry submission failed with status {}", response.statusCode());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Telemetry submission was interrupted");
            return false;
        } catch (Exception e) {
            LOGGER.warn("Failed to submit telemetry data", e);
            return false;
        }
    }

    record TelemetryData(
            @JsonProperty("system_id") String systemId,
            @JsonProperty("dt_version") String applicationVersion,
            @JsonProperty("db_type") String databaseType,
            @JsonProperty("db_version") String databaseVersion) {
    }

}
