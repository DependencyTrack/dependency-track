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
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CvssUtil;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.MDC;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.StringJoiner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialBackoff;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
import static org.dependencytrack.model.Severity.getSeverityByLevel;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV2Score;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV3Score;

public class OsvDownloadTask implements LoggableSubscriber {

    public static final Path DEFAULT_OSV_MIRROR_DIR = Config.getInstance().getDataDirectorty().toPath()
            .resolve("osv").toAbsolutePath();
    // Max size for ecosystem zip files: 1 GiB, some ecosystem files might reach this size in a few years
    // (Ubuntu is currently the largest one at ~380 MiB)
    private static final long MAX_ZIP_BYTES = 1024 * 1024 * 1024;
    private static final String OSV_FILENAME_PREFIX = "google-osv-";
    private static final Logger LOGGER = Logger.getLogger(OsvDownloadTask.class);
    private static final Retry DOWNLOAD_RETRY;
    private static final Retry REQUEST_RETRY;
    private Set<String> ecosystems;
    private String osvBaseUrl;
    private File outputDir;
    private final Clock clock;
    private final Path mirrorDirPath;
    private boolean aliasSyncEnabled;
    private long metricParseTime;
    private long metricDownloadTime;
    private boolean mirroredWithoutErrors = true;

    static {
        RetryRegistry registry = RetryRegistry.ofDefaults();
        final RetryConfig downloadRetryConfig = RetryConfig.custom()
                .intervalFunction(ofExponentialBackoff(
                        Duration.ofSeconds(2),
                        2,
                        Duration.ofSeconds(32)
                ))
                .maxAttempts(6)
                .retryExceptions(
                        SocketException.class, SocketTimeoutException.class,
                        NoRouteToHostException.class, ConnectTimeoutException.class
                )
                .build();
        DOWNLOAD_RETRY = registry.retry("osv-mirror-download", downloadRetryConfig);
        DOWNLOAD_RETRY.getEventPublisher()
                .onRetry(event -> LOGGER.warn("Encountered retryable exception; Retries: "
                        + event.getNumberOfRetryAttempts() + "; Next retry in: "
                        + event.getWaitInterval().toSeconds() + " s", event.getLastThrowable()))
                .onError(event -> LOGGER.error("Failed after "
                        + event.getNumberOfRetryAttempts() + " attempts"));

        final RetryConfig requestRetryConfig = RetryConfig.<CloseableHttpResponse>custom()
                .intervalFunction(ofExponentialBackoff(
                        Duration.ofSeconds(2),
                        2,
                        Duration.ofSeconds(32)
                ))
                .maxAttempts(6)
                .retryExceptions(
                        SocketException.class, SocketTimeoutException.class,
                        NoRouteToHostException.class, ConnectTimeoutException.class
                )
                .retryOnResult(response ->
                        // retries for response codes according to GCS status code documentation
                        // https://docs.cloud.google.com/storage/docs/json_api/v1/status-codes
                        Set.of(408, 429, 502, 503, 504).contains(response.getStatusLine().getStatusCode()))
                .build();
        REQUEST_RETRY = registry.retry("osv-mirror-request", requestRetryConfig);
        REQUEST_RETRY.getEventPublisher()
                .onRetry(event -> LOGGER.warn("Encountered retryable http status code; Retries: "
                        + event.getNumberOfRetryAttempts()
                        + "; Next retry in: " + event.getWaitInterval().toSeconds() + " s"))
                .onError(event -> LOGGER.error("Failed after "
                        + event.getNumberOfRetryAttempts() + " attempts"));
    }

    public OsvDownloadTask() {
        this(DEFAULT_OSV_MIRROR_DIR, Clock.systemUTC());
    }

    public OsvDownloadTask(final Path mirrorDirPath) {
        this(mirrorDirPath, Clock.systemUTC());
    }

    OsvDownloadTask(final Path mirrorDirPath, Clock clock) {
        this.mirrorDirPath = mirrorDirPath;
        this.clock = clock;
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(
                    VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(),
                    VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName());
            if (enabled != null) {
                final String ecosystemConfig = enabled.getPropertyValue();
                if (ecosystemConfig != null) {
                    ecosystems = Arrays.stream(ecosystemConfig.split(";"))
                            .map(String::trim)
                            .collect(Collectors.toSet());
                }
                this.osvBaseUrl = qm.getConfigProperty(
                        VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getGroupName(),
                        VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getPropertyName()).getPropertyValue();
                if (this.osvBaseUrl != null && !this.osvBaseUrl.endsWith("/")) {
                    this.osvBaseUrl += "/";
                }
                final ConfigProperty aliasSyncProperty = qm.getConfigProperty(
                        VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getGroupName(),
                        VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getPropertyName()
                );
                if (aliasSyncProperty != null) {
                    this.aliasSyncEnabled = "true".equals(aliasSyncProperty.getPropertyValue());
                }
            }
        }
    }

    @Override
    public void inform(Event e) {
        if (e instanceof OsvMirrorEvent) {
            if (ecosystems == null || ecosystems.isEmpty()) {
                LOGGER.info("Google OSV mirroring is disabled. No ecosystem selected.");
                return;
            }
            final long start = System.currentTimeMillis();
            setOutputDir(mirrorDirPath.toAbsolutePath().toString());
            LOGGER.info("Starting Google OSV mirroring for: " + ecosystems);
            ecosystems.forEach(this::processOsvEcosystem);
            final long end = System.currentTimeMillis();
            if (mirroredWithoutErrors) {
                LOGGER.info("Google OSV mirroring complete");
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.OSV_MIRROR)
                        .content("Mirroring of the Google OSV datastore for the selected ecosystems completed successfully")
                        .level(NotificationLevel.INFORMATIONAL)
                );
            } else {
                LOGGER.error("Google OSV mirroring completed with errors for one or more selected ecosystems, see above");
                Notification.dispatch(new Notification()
                        .scope(NotificationScope.SYSTEM)
                        .group(NotificationGroup.DATASOURCE_MIRRORING)
                        .title(NotificationConstants.Title.OSV_MIRROR)
                        .content("An error occurred while mirroring the Google OSV datastore. Check the log for details.")
                        .level(NotificationLevel.ERROR)
                );
            }
            LOGGER.info("Time spent (d/l):   " + metricDownloadTime + "ms");
            LOGGER.info("Time spent (parse): " + metricParseTime + "ms");
            LOGGER.info("Time spent (total): " + (end - start) + "ms");
        }
    }

    private void processOsvEcosystem(String ecosystem) {
        try (var ignoredMdcOsvEcosystem = MDC.putCloseable("osvEcosystem", ecosystem)) {
            final Instant currentTime = Instant.now(this.clock);
            if (shouldDoIncrementalUpdate(ecosystem, currentTime)) {
                String url = this.osvBaseUrl
                        + URLEncoder.encode(ecosystem, StandardCharsets.UTF_8).replace("+", "%20")
                        + "/modified_id.csv";
                LOGGER.info("Incremental update - Initiating download of " + url);
                doUpdate(url, ecosystem, true, currentTime);
            } else {
                String url = this.osvBaseUrl
                        + URLEncoder.encode(ecosystem, StandardCharsets.UTF_8).replace("+", "%20")
                        + "/all.zip";
                LOGGER.info("Full mirror - Initiating download of " + url);
                doUpdate(url, ecosystem, false, currentTime);
            }
        } catch (Throwable ex) {
            mirroredWithoutErrors = false;
            LOGGER.error("Exception while downloading/processing OSV data for " + ecosystem, ex);
        }
    }

    // Future improvement: add settings to enable or disable incremental updates and to set the cadence for full updates
    private boolean shouldDoIncrementalUpdate(String ecosystem, Instant currentTime) {
        final String fullMirrorOsvFileName = OSV_FILENAME_PREFIX + ecosystem + ".zip";
        final String modifiedOsvFileName = OSV_FILENAME_PREFIX + ecosystem + "-modified.csv";
        File fullMirrorFile = new File(outputDir, fullMirrorOsvFileName).getAbsoluteFile();

        if (!fullMirrorFile.exists() || !(fullMirrorFile.length() > 0))
            // the .zip file does not exist or is empty
            return false;

        Instant lastFullMirror = readTimestampFile(fullMirrorOsvFileName);
        Instant lastIncrementalMirror = readTimestampFile(modifiedOsvFileName);
        if (lastFullMirror == null || lastIncrementalMirror == null)
            // either one or both timestamp files are not present or timestamp parsing failed
            return false;

        if (currentTime.isBefore(lastFullMirror.plus(5, ChronoUnit.DAYS))) {
            // full mirror every five days in case any individual advisory files failed to be acquired or were skipped
            // during an incremental update
            LOGGER.info("Last successful full mirror for " + ecosystem + " was started at "
                    + lastFullMirror.truncatedTo(ChronoUnit.SECONDS)
                    + ", performing incremental update");
            return true;
        } else {
            LOGGER.info("Last successful full mirror for " + ecosystem + " was started at "
                    + lastFullMirror.truncatedTo(ChronoUnit.SECONDS)
                    + ", performing full update");
            return false;
        }
    }

    private void doUpdate(String url, String ecosystem, boolean incremental, Instant startTime) throws Throwable {
        File incrementalTimestampFile = new File(outputDir, OSV_FILENAME_PREFIX + ecosystem
                + "-modified.csv.ts").getAbsoluteFile();
        File fullTimestampFile = new File(outputDir, OSV_FILENAME_PREFIX + ecosystem
                + ".zip.ts").getAbsoluteFile();
        if (incremental) {
            Path modifiedCsv = DOWNLOAD_RETRY.executeCheckedSupplier(() -> downloadModifiedCsvFile(url, ecosystem));
            LOGGER.debug("Downloaded list of new or modified OSV advisories for " + ecosystem + " into " + modifiedCsv);
            final boolean success = processModifiedCsvFile(modifiedCsv, ecosystem);
            if (success) {
                LOGGER.info("Incremental update completed for " + ecosystem);
                writeTimestampFile(incrementalTimestampFile, startTime);
            }
        } else {
            Path osvZipFile = DOWNLOAD_RETRY.executeCheckedSupplier(() -> downloadOsvZipFile(url, ecosystem));
            LOGGER.debug("Downloaded OSV advisories for " + ecosystem + " into " + osvZipFile);
            final boolean success = processOsvZipFile(osvZipFile);
            if (success) {
                LOGGER.info("Full mirror completed for " + ecosystem);
                writeTimestampFile(fullTimestampFile, startTime);
                writeTimestampFile(incrementalTimestampFile, startTime);
            }
        }
    }

    private Path downloadModifiedCsvFile(String url, String ecosystem) throws Throwable {
        final long downloadStart = System.currentTimeMillis();
        final HttpUriRequest request = new HttpGet(url);
        try (CloseableHttpResponse response = REQUEST_RETRY.executeCheckedSupplier(() ->
                HttpClientPool.getClient().execute(request))) {
            final StatusLine status = response.getStatusLine();
            final HttpEntity entity = response.getEntity();
            try {
                LOGGER.info("Downloading...");
                if (status.getStatusCode() != HttpStatus.SC_OK) {
                    LOGGER.error("Download of modified_id.csv failed for: " + ecosystem + " - " +
                            status.getStatusCode() + " " + status.getReasonPhrase());
                    mirroredWithoutErrors = false;
                    throw new Exception("Download failed: " + status);
                }
                final String fileName = OSV_FILENAME_PREFIX + ecosystem + "-modified.csv";
                final File file = new File(outputDir, fileName).getAbsoluteFile();
                try (final InputStream in = response.getEntity().getContent()) {
                    Files.copy(in, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    metricDownloadTime += System.currentTimeMillis() - downloadStart;
                    return file.toPath();
                }
            } finally {
                EntityUtils.consumeQuietly(entity);
            }
        }
    }

    private boolean processModifiedCsvFile(Path modifiedCsvFilePath, String ecosystem) throws IOException {
        if (!Files.exists(modifiedCsvFilePath) || Files.isDirectory(modifiedCsvFilePath)
                || Files.size(modifiedCsvFilePath) == 0) {
            LOGGER.warn("Downloaded modified OSV .csv file is not processable, skipping: "
                    + modifiedCsvFilePath.getFileName());
            mirroredWithoutErrors = false;
            return false;
        }
        return downloadAndProcessModifiedOsvAdvisories(modifiedCsvFilePath, ecosystem);
    }

    private boolean downloadAndProcessModifiedOsvAdvisories(Path modifiedCsvFilePath, String ecosystem) throws IOException {
        Instant lastUpdate = readTimestampFile(modifiedCsvFilePath.getFileName().toString());
        if (lastUpdate == null) {
            // Should never be reached as the .ts file is already checked in shouldDoIncrementalUpdate()
            LOGGER.error("Could not obtain last update time from timestamp file due to previous error,"
                    + " using fallback timestamp");
            lastUpdate = Instant.EPOCH;
        }
        final ArrayList<String> modifiedIds = parseModifiedOsvAdvisoryCsv(modifiedCsvFilePath, lastUpdate);
        if (modifiedIds.isEmpty()) {
            LOGGER.info("No new or modified advisories since the last update, skipping");
            return true;
        }
        LOGGER.info("Downloading and processing new or modified advisories");
        final OsvAdvisoryParser parser = new OsvAdvisoryParser();
        final ArrayList<String> unsuccessfulIds = new ArrayList<>();
        int count = 0;
        int lastLoggedPercent = 0;
        for (String id : modifiedIds) {
            final long downloadStartTime = System.currentTimeMillis();
            String url = this.osvBaseUrl
                    + URLEncoder.encode(ecosystem, StandardCharsets.UTF_8).replace("+", "%20")
                    + "/" + URLEncoder.encode(id, StandardCharsets.UTF_8).replace("+", "%20")
                    + ".json";
            final HttpUriRequest request = new HttpGet(url);
            try (CloseableHttpResponse response = REQUEST_RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request))) {
                final StatusLine status = response.getStatusLine();
                final HttpEntity entity = response.getEntity();
                try {
                    if (status.getStatusCode() != HttpStatus.SC_OK) {
                        LOGGER.error("Download of advisory file failed for: " + url + " - " +
                                status.getStatusCode() + " " + status.getReasonPhrase());
                        mirroredWithoutErrors = false;
                        unsuccessfulIds.add(id);
                        continue;
                    }
                    if (unsuccessfulIds.size() > 5) {
                        LOGGER.error("Failed to acquire more than 5 out of " + modifiedIds.size() + " advisories, aborting."
                                + " IDs that could not be acquired: " + unsuccessfulIds);
                        return false;
                    }
                    try (final InputStream in = response.getEntity().getContent()) {
                        final BufferedReader reader = new BufferedReader(
                                new InputStreamReader(in, StandardCharsets.UTF_8), 8192
                        );
                        final long downloadEndTime = System.currentTimeMillis();
                        metricDownloadTime += downloadEndTime - downloadStartTime;
                        final JSONObject json = new JSONObject(new JSONTokener(reader));
                        processOsvAdvisoryJsonFromCsv(json, parser);
                        if (modifiedIds.size() >= 500) {
                            count++;
                            final int totalCount = modifiedIds.size() - unsuccessfulIds.size();
                            lastLoggedPercent = logProgressPercent(count, totalCount, lastLoggedPercent);
                        }
                        final long parseEndtime = System.currentTimeMillis();
                        metricParseTime += parseEndtime - downloadEndTime;
                    }
                } catch (JSONException e) {
                    LOGGER.warn("Skipping advisory " + id + " due to: ", e);
                } finally {
                    EntityUtils.consumeQuietly(entity);
                }
            } catch (Throwable e) {
                LOGGER.error("Download or processing failed with an unexpected error: ", e);
                mirroredWithoutErrors = false;
            }
        }
        if (!unsuccessfulIds.isEmpty()) {
            LOGGER.warn("Advisories with the following IDs could not be acquired: " + unsuccessfulIds);
        }
        return true;
    }

    private ArrayList<String> parseModifiedOsvAdvisoryCsv(Path modifiedCsvFilePath, Instant lastUpdate) throws IOException {
        ArrayList<String> modifiedIds = new ArrayList<>();
        final long parseStartTime = System.currentTimeMillis();
        LOGGER.info("Parsing " + modifiedCsvFilePath.getFileName() + " to obtain modified OSV advisory IDs");
        try (BufferedReader reader = Files.newBufferedReader(modifiedCsvFilePath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                String[] parts = line.split(",", 2);
                if (parts.length != 2) {
                    continue;
                }
                String timestampStr = parts[0].trim();
                String id = parts[1].trim();
                try {
                    Instant modifiedTimestamp = Instant.parse(timestampStr);
                    if (lastUpdate != null && modifiedTimestamp.isBefore(lastUpdate)) {
                        // found an entry that was before the last update, the list is sorted with new entries at the top
                        break;
                    }
                    // For some ecosystems more than 10k advisories (npm sometimes has 40k+) might be modified within a day.
                    // Those mass updates are usually non-critical i.e. versions being added after a new release, but
                    // they might also contain many new "malicious package" notices for npm
                    if (modifiedIds.size() >= 10000) {
                        LOGGER.warn("Cutting off after 10k new or modified advisories, "
                                + "remaining updates will be retrieved in full mirror every 5 days");
                        break;
                    }
                    modifiedIds.add(id);
                } catch (DateTimeParseException e) {
                    LOGGER.error("Skipping CSV line with invalid timestamp: " + line);
                }
            }
        }
        if (!modifiedIds.isEmpty()) {
            LOGGER.info("Found " + modifiedIds.size() + " advisories that were added or modified since the last update "
                    + "at " + lastUpdate);
        }
        metricParseTime += System.currentTimeMillis() - parseStartTime;
        return modifiedIds;
    }

    private void processOsvAdvisoryJsonFromCsv(JSONObject modifiedOsvAdvisory, OsvAdvisoryParser parser) {
        try {
            final String advisoryId = modifiedOsvAdvisory.optString("id", "unknown");
            try (var ignoredMdcVulnId = MDC.putCloseable(MDC_VULN_ID, advisoryId)) {
                final OsvAdvisory osvAdvisory = parser.parse(modifiedOsvAdvisory);
                if (osvAdvisory != null) {
                    updateDatasource(osvAdvisory);
                } else {
                    LOGGER.debug("Advisory: " + advisoryId + " was not processed further (withdrawn or parsing failed)");
                }
            }
        } catch (RuntimeException e) {
            LOGGER.error("Unexpected error while processing OSV advisory: ", e);
            mirroredWithoutErrors = false;
        }
    }

    private Path downloadOsvZipFile(String url, String ecosystem) throws Throwable {
        final long downloadStart = System.currentTimeMillis();
        final HttpUriRequest request = new HttpGet(url);
        try (CloseableHttpResponse response = REQUEST_RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request))) {
            final StatusLine status = response.getStatusLine();
            final HttpEntity entity = response.getEntity();
            try {
                LOGGER.info("Downloading...");
                if (status.getStatusCode() != HttpStatus.SC_OK) {
                    LOGGER.error("Download of all.zip failed for: " + ecosystem + " - " +
                            status.getStatusCode() + " " + status.getReasonPhrase());
                    mirroredWithoutErrors = false;
                    throw new Exception("Download failed: " + status);
                }
                final long contentLength = entity.getContentLength();
                LOGGER.debug("HTTP contentLength for " + ecosystem + ": " + contentLength);
                if (contentLength > MAX_ZIP_BYTES) {
                    LOGGER.error("zip file for " + ecosystem + " is too large: " + contentLength
                            + " bytes (limit " + MAX_ZIP_BYTES + ")");
                    mirroredWithoutErrors = false;
                    throw new Exception("Download failed, zip file too large: " + entity.getContentLength());
                }
                final String fileName = OSV_FILENAME_PREFIX + ecosystem + ".zip";
                final File file = new File(outputDir, fileName).getAbsoluteFile();
                try (final InputStream in = response.getEntity().getContent()) {
                    Files.copy(in, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    metricDownloadTime += System.currentTimeMillis() - downloadStart;
                    return file.toPath();
                }
            } finally {
                EntityUtils.consumeQuietly(entity);
            }
        }
    }

    private boolean processOsvZipFile(Path filePath) throws IOException {
        final long start = System.currentTimeMillis();
        if (!Files.exists(filePath) || Files.isDirectory(filePath) || Files.size(filePath) == 0) {
            LOGGER.warn("Downloaded OSV .zip file is not processable, skipping: " + filePath.getFileName());
            mirroredWithoutErrors = false;
            return false;
        }
        final int count;
        try (ZipFile zip = new ZipFile(filePath.toFile())) {
            count = zip.size();
        }
        LOGGER.info("Decompressing " + filePath.getFileName());
        try (final var in = Files.newInputStream(filePath);
             final var bufferedIn = new BufferedInputStream(in);
             final var zipInput = new ZipInputStream(bufferedIn)) {
            unzipOsvZipFile(zipInput, count);
        }
        final long end = System.currentTimeMillis();
        metricParseTime += end - start;
        return true;
    }

    private void unzipOsvZipFile(ZipInputStream zipIn, int totalCount) throws IOException {
        final Pattern jsonPattern = Pattern.compile("\\.json$", Pattern.CASE_INSENSITIVE);
        final OsvAdvisoryParser parser = new OsvAdvisoryParser();
        ZipEntry zipEntry;
        int lastLoggedPercent = 0;
        int count = 0;
        LOGGER.info("Parsing OSV advisory JSON files and updating the database, total count: " + totalCount);
        while ((zipEntry = zipIn.getNextEntry()) != null) {
            try {
                if (zipEntry.isDirectory()) {
                    LOGGER.warn("Skipped directory: " + zipEntry.getName());
                    continue;
                }
                final String entryName = zipEntry.getName();
                if (!jsonPattern.matcher(entryName).find()) {
                    LOGGER.warn("Skipped non-JSON entry: " + entryName);
                    continue;
                }
                processOsvAdvisoryJsonFromZip(zipIn, entryName, parser);
                count++;
                lastLoggedPercent = logProgressPercent(count, totalCount, lastLoggedPercent);
            } finally {
                zipIn.closeEntry();
            }
        }
    }

    private int logProgressPercent(int currentCount, int totalCount, int lastLoggedPercent) {
        final int currentProcessedPercentage = (currentCount * 100) / totalCount;
        if (currentProcessedPercentage >= lastLoggedPercent + 10) {
            LOGGER.info("Processed " + currentCount + "/" + totalCount + " advisories (" + currentProcessedPercentage + "%)");
            lastLoggedPercent = currentProcessedPercentage;
        }
        return lastLoggedPercent;
    }

    private void processOsvAdvisoryJsonFromZip(ZipInputStream zipIn, String entryName, OsvAdvisoryParser parser) {
        try {
            final BufferedReader reader = new BufferedReader(
                    new InputStreamReader(zipIn, StandardCharsets.UTF_8), 8192
            );
            final JSONObject json = new JSONObject(new JSONTokener(reader));
            final String advisoryId = json.optString("id", "unknown");
            try (var ignoredMdcVulnId = MDC.putCloseable(MDC_VULN_ID, advisoryId)) {
                final OsvAdvisory osvAdvisory = parser.parse(json);
                if (osvAdvisory != null) {
                    updateDatasource(osvAdvisory);
                } else {
                    LOGGER.debug("Advisory from entry: " + entryName +
                            " was not processed further (withdrawn or parsing error)");
                }
            }
        } catch (JSONException e) {
            LOGGER.error("JSON parsing error for entry: " + entryName, e);
            mirroredWithoutErrors = false;
        } catch (RuntimeException e) {
            LOGGER.error("Unexpected error processing entry: " + entryName, e);
            mirroredWithoutErrors = false;
        }
    }

    private Instant readTimestampFile(final String filename) {
        final String timestampFileName = filename + ".ts";
        File timestampFile = new File(outputDir, timestampFileName).getAbsoluteFile();
        if (!timestampFile.exists() || timestampFile.length() == 0) {
            return null;
        }
        try (BufferedReader tsBufReader = Files.newBufferedReader(timestampFile.toPath())) {
            String text = tsBufReader.readLine();
            return Instant.parse(text);
        } catch (IOException e) {
            LOGGER.error("Failed to open .ts file " + timestampFile);
            return null;
        } catch (DateTimeParseException e) {
            LOGGER.error("Failed to parse timestamp in .ts file " + timestampFile);
            return null;
        }
    }

    private void writeTimestampFile(final File file, Instant modificationTime) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(modificationTime.truncatedTo(ChronoUnit.MILLIS).toString());
        }
    }

    private void setOutputDir(final String outputDirPath) {
        outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            if (outputDir.mkdirs()) {
                LOGGER.info("Mirrored data directory created successfully");
            }
        }
    }

    public void updateDatasource(final OsvAdvisory advisory) {

        try (QueryManager qm = new QueryManager()) {

            LOGGER.debug("Synchronizing Google OSV advisory: " + advisory.getId());
            final Vulnerability vulnerability = mapAdvisoryToVulnerability(advisory);
            final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(vulnerability.getSource(), vulnerability.getVulnId()));
            final Vulnerability existingVulnerability = qm.getVulnerabilityByVulnId(vulnerability.getSource(), vulnerability.getVulnId());
            final Vulnerability.Source vulnerabilitySource = extractSource(advisory.getId());
            final ConfigPropertyConstants vulnAuthoritativeSourceToggle = switch (vulnerabilitySource) {
                case NVD -> ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
                case GITHUB -> ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
                default -> VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
            };
            final boolean vulnAuthoritativeSourceEnabled = Boolean.parseBoolean(qm.getConfigProperty(vulnAuthoritativeSourceToggle.getGroupName(), vulnAuthoritativeSourceToggle.getPropertyName()).getPropertyValue());
            Vulnerability synchronizedVulnerability = existingVulnerability;
            if (shouldUpdateExistingVulnerability(existingVulnerability, vulnerabilitySource, vulnAuthoritativeSourceEnabled)) {
                synchronizedVulnerability = qm.synchronizeVulnerability(vulnerability, false);
                if (synchronizedVulnerability == null) return; // Exit if nothing to update
            }

            if (aliasSyncEnabled && advisory.getAliases() != null) {
                for (int i = 0; i < advisory.getAliases().size(); i++) {
                    final String alias = advisory.getAliases().get(i);
                    final VulnerabilityAlias vulnerabilityAlias = new VulnerabilityAlias();

                    // OSV will use IDs of other vulnerability databases for its
                    // primary advisory ID (e.g. GHSA-45hx-wfhj-473x). We need to ensure
                    // that we don't falsely report GHSA IDs as stemming from OSV.
                    switch (vulnerabilitySource) {
                        case NVD -> vulnerabilityAlias.setCveId(advisory.getId());
                        case GITHUB -> vulnerabilityAlias.setGhsaId(advisory.getId());
                        default -> vulnerabilityAlias.setOsvId(advisory.getId());
                    }

                    if (alias.startsWith("CVE") && Vulnerability.Source.NVD != vulnerabilitySource) {
                        vulnerabilityAlias.setCveId(alias);
                        qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                    } else if (alias.startsWith("GHSA") && Vulnerability.Source.GITHUB != vulnerabilitySource) {
                        vulnerabilityAlias.setGhsaId(alias);
                        qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                    }

                    //TODO - OSV supports GSD and DLA/DSA identifiers (possibly others). Determine how to handle.
                }
            }

            List<VulnerableSoftware> vsList = new ArrayList<>();
            for (OsvAffectedPackage osvAffectedPackage : advisory.getAffectedPackages()) {
                VulnerableSoftware vs = mapAffectedPackageToVulnerableSoftware(qm, osvAffectedPackage);
                if (vs != null) {
                    vsList.add(vs);
                }
            }
            qm.persist(vsList);
            qm.updateAffectedVersionAttributions(synchronizedVulnerability, vsList, Vulnerability.Source.OSV);
            vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList, Vulnerability.Source.OSV);
            synchronizedVulnerability.setVulnerableSoftware(vsList);
            qm.persist(synchronizedVulnerability);
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    private boolean shouldUpdateExistingVulnerability(Vulnerability existingVulnerability, Vulnerability.Source vulnerabilitySource, boolean vulnAuthoritativeSourceEnabled) {
        return (Vulnerability.Source.OSV == vulnerabilitySource) // Non GHSA nor NVD
                || (existingVulnerability == null) // Vuln is not replicated yet or declared by authoritative source with appropriate state
                || !vulnAuthoritativeSourceEnabled; // Vuln has been replicated but authoritative source is disabled
    }

    public Vulnerability mapAdvisoryToVulnerability(final OsvAdvisory advisory) {

        final Vulnerability vuln = new Vulnerability();
        if (advisory.getId() != null) {
            vuln.setSource(extractSource(advisory.getId()));
        }
        vuln.setVulnId(String.valueOf(advisory.getId()));
        vuln.setTitle(advisory.getSummary());
        vuln.setDescription(advisory.getDetails());
        vuln.setPublished(Date.from(advisory.getPublished().toInstant()));
        vuln.setUpdated(Date.from(advisory.getModified().toInstant()));

        if (advisory.getCredits() != null) {
            vuln.setCredits(String.join(", ", advisory.getCredits()));
        }

        if (advisory.getReferences() != null && !advisory.getReferences().isEmpty()) {
            final StringBuilder sb = new StringBuilder();
            final StringJoiner sj = new StringJoiner("\n");
            for (String ref : advisory.getReferences()) {
                sb.append("* [").append(ref).append("](").append(ref).append(")");
                sj.add(sb.toString());
                sb.setLength(0);
            }
            vuln.setReferences(sj.toString());
        }

        if (advisory.getCweIds() != null) {
            for (int i = 0; i < advisory.getCweIds().size(); i++) {
                final Cwe cwe = CweResolver.getInstance().lookup(advisory.getCweIds().get(i));
                if (cwe != null) {
                    vuln.addCwe(cwe);
                }
            }
        }
        vuln.setSeverity(calculateOSVSeverity(advisory));
        vuln.setCvssV2Vector(advisory.getCvssV2Vector());
        vuln.setCvssV3Vector(advisory.getCvssV3Vector());
        return vuln;
    }

    // calculate severity of vulnerability on priority-basis (database, ecosystem)
    public Severity calculateOSVSeverity(OsvAdvisory advisory) {

        // derive from database_specific cvss v3 vector if available
        if (advisory.getCvssV3Vector() != null) {
            var cvss = CvssUtil.parse(advisory.getCvssV3Vector());
            if (cvss != null) {
                var score = cvss.getBakedScores();
                return normalizedCvssV3Score(score.getOverallScore());
            } else {
                LOGGER.warn("Unable to determine severity from CVSSv3 vector: " + advisory.getCvssV3Vector());
            }
        }
        // derive from database_specific cvss v2 vector if available
        if (advisory.getCvssV2Vector() != null) {
            var cvss = CvssUtil.parse(advisory.getCvssV2Vector());
            if (cvss != null) {
                var score = cvss.getBakedScores();
                return normalizedCvssV2Score(score.getOverallScore());
            } else {
                LOGGER.warn("Unable to determine severity from CVSSv2 vector: " + advisory.getCvssV2Vector());
            }
        }
        // get database_specific severity string if available
        if (advisory.getSeverity() != null) {
            if (advisory.getSeverity().equalsIgnoreCase("CRITICAL")) {
                return Severity.CRITICAL;
            } else if (advisory.getSeverity().equalsIgnoreCase("HIGH")) {
                return Severity.HIGH;
            } else if (advisory.getSeverity().equalsIgnoreCase("MODERATE")) {
                return Severity.MEDIUM;
            } else if (advisory.getSeverity().equalsIgnoreCase("LOW")) {
                return Severity.LOW;
            }
        }
        // get largest ecosystem_specific severity from its affected packages
        if (!advisory.getAffectedPackages().isEmpty()) {
            List<Integer> severityLevels = new ArrayList<>();
            for (OsvAffectedPackage vuln : advisory.getAffectedPackages()) {
                severityLevels.add(vuln.getSeverity().getLevel());
            }
            Collections.sort(severityLevels);
            return getSeverityByLevel(severityLevels.getLast());
        }
        return Severity.UNASSIGNED;
    }

    public Vulnerability.Source extractSource(String vulnId) {
        final String sourceId = vulnId.split("-")[0];
        return switch (sourceId) {
            case "GHSA" -> Vulnerability.Source.GITHUB;
            case "CVE" -> Vulnerability.Source.NVD;
            default -> Vulnerability.Source.OSV;
        };
    }

    public VulnerableSoftware mapAffectedPackageToVulnerableSoftware(final QueryManager qm, final OsvAffectedPackage affectedPackage) {
        if (affectedPackage.getPurl() == null) {
            LOGGER.debug("No PURL provided for affected package " + affectedPackage.getPackageName() + " - skipping");
            return null;
        }

        final PackageURL purl;
        try {
            purl = new PackageURL(affectedPackage.getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Invalid PURL provided for affected package  " + affectedPackage.getPackageName() + " - skipping", e);
            return null;
        }

        // Other sources do not populate the versionStartIncluding with 0.
        // Semantically, versionStartIncluding=null is equivalent to >=0.
        // Omit zero values here for consistency's sake.
        final String versionStartIncluding = Optional.ofNullable(affectedPackage.getLowerVersionRange())
                .filter(version -> !"0".equals(version))
                .orElse(null);
        final String versionEndExcluding = affectedPackage.getUpperVersionRangeExcluding();
        final String versionEndIncluding = affectedPackage.getUpperVersionRangeIncluding();

        VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(purl.getType(), purl.getNamespace(), purl.getName(),
                purl.getVersion(), versionEndExcluding, versionEndIncluding, null, versionStartIncluding);
        if (vs != null) {
            return vs;
        }

        vs = new VulnerableSoftware();
        vs.setPurlType(purl.getType());
        vs.setPurlNamespace(purl.getNamespace());
        vs.setPurlName(purl.getName());
        vs.setPurl(purl.canonicalize());
        vs.setVulnerable(true);
        vs.setVersion(affectedPackage.getVersion());
        vs.setVersionStartIncluding(versionStartIncluding);
        vs.setVersionEndExcluding(versionEndExcluding);
        vs.setVersionEndIncluding(versionEndIncluding);
        return vs;
    }

    public List<String> getEcosystems() {
        ArrayList<String> ecosystems = new ArrayList<>();
        String url = this.osvBaseUrl + "ecosystems.txt";
        HttpUriRequest request = new HttpGet(url);
        try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            final StatusLine status = response.getStatusLine();
            if (status.getStatusCode() == HttpStatus.SC_OK) {
                try (InputStream in = response.getEntity().getContent();
                     Scanner scanner = new Scanner(in, StandardCharsets.UTF_8)) {
                    while (scanner.hasNextLine()) {
                        final String line = scanner.nextLine();
                        if (!line.isBlank()) {
                            ecosystems.add(line.trim());
                        }
                    }
                }
            } else {
                LOGGER.error("Ecosystem download failed : " + status.getStatusCode() + ": " + status.getReasonPhrase());
            }
        } catch (Exception ex) {
            LOGGER.error("Exception while executing Http request for ecosystems", ex);
        }
        return ecosystems;
    }

    public Set<String> getEnabledEcosystems() {
        return Optional.ofNullable(this.ecosystems)
                .orElseGet(Collections::emptySet);
    }

}
