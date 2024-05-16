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
import alpine.common.metrics.Metrics;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import io.github.resilience4j.micrometer.tagged.TaggedRetryMetrics;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ConnectTimeoutException;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.NistApiMirrorEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.nvd.NvdParser;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.listener.IndexingInstanceLifecycleListener;
import org.dependencytrack.persistence.listener.L2CacheEvictingInstanceLifecycleListener;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.zip.GZIPInputStream;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialBackoff;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.datanucleus.PropertyNames.PROPERTY_RETAIN_VALUES;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_DOWNLOAD_FEEDS;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_FEEDS_URL;

/**
 * Subscriber task that performs a mirror of the National Vulnerability Database.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class NistMirrorTask extends AbstractNistMirrorTask implements LoggableSubscriber {

    private enum ResourceType {
        CVE_YEAR_DATA,
        CVE_MODIFIED_DATA,
        CVE_META,
        CPE,
        CWE,
        NONE // DO NOT PARSE THIS TYPE
    }

    public static final Path DEFAULT_NVD_MIRROR_DIR = Config.getInstance().getDataDirectorty().toPath().resolve("nist").toAbsolutePath();
    private static final String CVE_JSON_11_MODIFIED_URL = "/json/cve/1.1/nvdcve-1.1-modified.json.gz";
    private static final String CVE_JSON_11_BASE_URL = "/json/cve/1.1/nvdcve-1.1-%d.json.gz";
    private static final String CVE_JSON_11_MODIFIED_META = "/json/cve/1.1/nvdcve-1.1-modified.meta";
    private static final String CVE_JSON_11_BASE_META = "/json/cve/1.1/nvdcve-1.1-%d.meta";
    private static final int START_YEAR = 2002;
    private final int endYear = Calendar.getInstance().get(Calendar.YEAR);

    private final boolean isEnabled;
    private final boolean isApiEnabled;
    private final boolean isApiDownloadFeeds;
    private String nvdFeedsUrl;
    private File outputDir;
    private long metricParseTime;
    private long metricDownloadTime;

    private static final Logger LOGGER = Logger.getLogger(NistMirrorTask.class);
    private static final Retry RETRY;

    static {
        final RetryRegistry retryRegistry = RetryRegistry.of(RetryConfig.<CloseableHttpResponse>custom()
                .intervalFunction(ofExponentialBackoff(
                        /* initialInterval */ Duration.ofSeconds(1),
                        /* multiplier */ 2,
                        /* maxInterval */ Duration.ofSeconds(32)
                ))
                .failAfterMaxAttempts(true)
                .maxAttempts(6)
                .retryOnException(exception -> exception instanceof ConnectTimeoutException
                        || exception instanceof NoRouteToHostException
                        || exception instanceof SocketTimeoutException)
                .retryOnResult(response -> 403 == response.getStatusLine().getStatusCode()
                        || 429 == response.getStatusLine().getStatusCode())
                .build());
        RETRY = retryRegistry.retry("nvd-feeds");
        RETRY.getEventPublisher()
                .onRetry(event -> LOGGER.warn("Encountered retryable exception; Will execute retry #%d in %s"
                        .formatted(event.getNumberOfRetryAttempts(), event.getWaitInterval()), event.getLastThrowable()))
                .onError(event -> LOGGER.error("Failed after %d retry attempts"
                        .formatted(event.getNumberOfRetryAttempts()), event.getLastThrowable()));
        TaggedRetryMetrics.ofRetryRegistry(retryRegistry)
                .bindTo(Metrics.getRegistry());
    }

    private final Path mirrorDirPath;
    private boolean mirroredWithoutErrors = true;

    public NistMirrorTask() {
        this(DEFAULT_NVD_MIRROR_DIR);
    }

    NistMirrorTask(final Path mirrorDirPath) {
        this.mirrorDirPath = mirrorDirPath;

        try (final QueryManager qm = new QueryManager()) {
            this.isEnabled = qm.isEnabled(VULNERABILITY_SOURCE_NVD_ENABLED);
            this.isApiEnabled = qm.isEnabled(VULNERABILITY_SOURCE_NVD_API_ENABLED);
            this.isApiDownloadFeeds = qm.isEnabled(VULNERABILITY_SOURCE_NVD_API_DOWNLOAD_FEEDS);
            this.nvdFeedsUrl = qm.getConfigProperty(
                    VULNERABILITY_SOURCE_NVD_FEEDS_URL.getGroupName(),
                    VULNERABILITY_SOURCE_NVD_FEEDS_URL.getPropertyName()
            ).getPropertyValue();
            if (this.nvdFeedsUrl.endsWith("/")) {
                this.nvdFeedsUrl = this.nvdFeedsUrl.substring(0, this.nvdFeedsUrl.length()-1);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof NistMirrorEvent && this.isEnabled) {
            if (isApiEnabled) {
                Event.dispatch(new NistApiMirrorEvent());

                if (!isApiDownloadFeeds) {
                    LOGGER.debug("""
                            Not downloading feeds because mirroring via NVD is enabled,\
                            but additional feed download is not; It can be enabled in \
                            the settings if desired""");
                    return;
                }
            } else {
                LOGGER.warn("""
                        The NVD is planning to retire the legacy data feeds used by Dependency-Track \
                        (https://nvd.nist.gov/General/News/change-timeline); Consider enabling mirroring \
                        via NVD REST API in the settings: https://docs.dependencytrack.org/datasources/nvd/#mirroring-via-nvd-rest-api""");
            }

            final long start = System.currentTimeMillis();
            LOGGER.info("Starting NIST mirroring task");
            final File mirrorPath = mirrorDirPath.toFile();
            setOutputDir(mirrorPath.getAbsolutePath());
            getAllFiles();
            final long end = System.currentTimeMillis();
            LOGGER.info("NIST mirroring complete");
            LOGGER.info("Time spent (d/l):   " + metricDownloadTime + "ms");
            if (!isApiEnabled) {
                LOGGER.info("Time spent (parse): " + metricParseTime + "ms");
                Event.dispatch(new EpssMirrorEvent());
            }
            LOGGER.info("Time spent (total): " + (end - start) + "ms");
        }
    }

    /**
     * Download all NVD XML and JSON feeds from NIST.
     */
    private void getAllFiles() {
        final Date currentDate = new Date();
        LOGGER.info("Downloading files at " + currentDate);
        for (int i = endYear; i >= START_YEAR; i--) {
            // Download JSON 1.1 year feeds in reverse order
            final String json11BaseUrl = this.nvdFeedsUrl + CVE_JSON_11_BASE_URL.replace("%d", String.valueOf(i));
            final String cve11BaseMetaUrl = this.nvdFeedsUrl + CVE_JSON_11_BASE_META.replace("%d", String.valueOf(i));
            doDownload(json11BaseUrl, ResourceType.CVE_YEAR_DATA);
            doDownload(cve11BaseMetaUrl, ResourceType.CVE_META);
        }

        // Modified feeds must be mirrored last, otherwise we risk more recent data being
        // overwritten by old or stale data: https://github.com/DependencyTrack/dependency-track/pull/1929#issuecomment-1743579226
        doDownload(this.nvdFeedsUrl + CVE_JSON_11_MODIFIED_URL, ResourceType.CVE_MODIFIED_DATA);
        doDownload(this.nvdFeedsUrl + CVE_JSON_11_MODIFIED_META, ResourceType.CVE_META);

        if (mirroredWithoutErrors) {
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.DATASOURCE_MIRRORING)
                    .title(NotificationConstants.Title.NVD_MIRROR)
                    .content("Mirroring of the National Vulnerability Database completed successfully")
                    .level(NotificationLevel.INFORMATIONAL)
            );
        }
    }

    /**
     * Defines the output directory where the mirrored files will be stored.
     * Creates the directory if non-existent.
     * @param outputDirPath the target output directory path
     */
    private void setOutputDir(final String outputDirPath) {
        outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            if (outputDir.mkdirs()) {
                LOGGER.info("Mirrored data directory created successfully");
            }
        }
    }

    /**
     * Performs a HTTP HEAD request to determine if a URL has updates since the last
     * time it was requested.
     * @param cveUrl the URL to perform a HTTP HEAD request on
     * @return the length of the content if it were to be downloaded
     */
    private long checkHead(final String cveUrl) {
        final HttpUriRequest request = new HttpHead(cveUrl);
        try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            return Long.valueOf(response.getFirstHeader(HttpHeaders.CONTENT_LENGTH).getValue());
        } catch (IOException | NumberFormatException | NullPointerException e) {
            LOGGER.error("Failed to determine content length");
        }
        return 0;
    }

    /**
     * Performs a download of specified URL.
     * @param urlString the URL contents to download
     */
    private void doDownload(final String urlString, final ResourceType resourceType) {
        File file;
        try {
            final URL url = URI.create(urlString).toURL();
            String filename = url.getFile();
            filename = filename.substring(filename.lastIndexOf('/') + 1);
            file = new File(outputDir, filename).getAbsoluteFile();
            if (file.exists()) {
                long modificationTime = 0;
                File timestampFile = new File(outputDir, filename + ".ts");
                if(timestampFile.exists()) {
                    BufferedReader tsBufReader = new BufferedReader(new FileReader(timestampFile));
                    String text = tsBufReader.readLine();
                    modificationTime = Long.parseLong(text);
                }

                if (System.currentTimeMillis() < ((86400000 * 5) + modificationTime)) {
                    if (ResourceType.CVE_YEAR_DATA == resourceType) {
                        LOGGER.info("Retrieval of " + filename + " not necessary. Will use modified feed for updates.");
                        return;
                    } else if (ResourceType.CVE_META == resourceType) {
                        return; // no need to log
                    } else if (ResourceType.CVE_MODIFIED_DATA == resourceType) {
                        final long fileSize = checkHead(urlString);
                        if (file.length() == fileSize) {
                            LOGGER.info("Using cached version of " + filename);
                            return;
                        }
                    }
                }
            }
            final long start = System.currentTimeMillis();
            LOGGER.info("Initiating download of " + url.toExternalForm());
            final HttpUriRequest request = new HttpGet(urlString);
            try (final CloseableHttpResponse response = RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request))) {
                final StatusLine status = response.getStatusLine();
                final long end = System.currentTimeMillis();
                metricDownloadTime += end - start;
                if (status.getStatusCode() == HttpStatus.SC_OK) {
                    LOGGER.info("Downloading...");
                    try (InputStream in = response.getEntity().getContent()) {
                        File temp = File.createTempFile(filename, null);
                        FileUtils.copyInputStreamToFile(in, temp);
                        Files.copy(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
                        Files.delete(temp.toPath());
                        if (ResourceType.CVE_YEAR_DATA == resourceType || ResourceType.CVE_MODIFIED_DATA == resourceType) {
                            // Sets the last modified date to 0. Upon a successful parse, it will be set back to its original date.
                            File timestampFile = new File(outputDir, filename + ".ts");
                            writeTimeStampFile(timestampFile, 0L);
                        }
                    }
                } else if (response.getStatusLine().getStatusCode() == 403) {
                    mirroredWithoutErrors = false;
                    final String detailMessage = "This may occur if the NVD is throttling connections due to excessive load or repeated " +
                            "connections from the same IP address or as a result of firewall or proxy authentication failures";
                    LOGGER.warn("Unable to download - HTTP Response 403: " + status.getReasonPhrase());
                    LOGGER.warn(detailMessage);
                    Notification.dispatch(new Notification()
                            .scope(NotificationScope.SYSTEM)
                            .group(NotificationGroup.DATASOURCE_MIRRORING)
                            .title(NotificationConstants.Title.NVD_MIRROR)
                            .content("An error occurred mirroring the contents of the National Vulnerability Database. Check log for details. HTTP Response: " + status.getStatusCode() + ". " + detailMessage)
                            .level(NotificationLevel.ERROR)
                    );
                } else {
                    mirroredWithoutErrors = false;
                    LOGGER.warn("Unable to download - HTTP Response " + status.getStatusCode() + ": " + status.getReasonPhrase());
                    Notification.dispatch(new Notification()
                            .scope(NotificationScope.SYSTEM)
                            .group(NotificationGroup.DATASOURCE_MIRRORING)
                            .title(NotificationConstants.Title.NVD_MIRROR)
                            .content("An error occurred mirroring the contents of the National Vulnerability Database. Check log for details. HTTP Response: " + status.getStatusCode())
                            .level(NotificationLevel.ERROR)
                    );
                }
            }

            if (file.getName().endsWith(".gz")) {
                uncompress(file, resourceType);
            }
        } catch (Throwable e) {
            mirroredWithoutErrors = false;
            LOGGER.error("Download failed : " + e.getMessage());
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.DATASOURCE_MIRRORING)
                    .title(NotificationConstants.Title.NVD_MIRROR)
                    .content("An error occurred mirroring the contents of the National Vulnerability Database. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Extracts a GZip file.
     * @param file the file to extract
     */
    private void uncompress(final File file, final ResourceType resourceType) {
        final File uncompressedFile = new File(file.getAbsolutePath().replaceAll(".gz", ""));
        try (final var gzis = new GZIPInputStream(Files.newInputStream(file.toPath()));
             final var out = Files.newOutputStream(uncompressedFile.toPath())) {
            LOGGER.info("Uncompressing " + file.getName());
            IOUtils.copy(gzis, out);
        } catch (IOException ex) {
            mirroredWithoutErrors = false;
            LOGGER.error("An error occurred uncompressing NVD payload", ex);
        }

        final long start = System.currentTimeMillis();
        if (ResourceType.CVE_YEAR_DATA == resourceType || ResourceType.CVE_MODIFIED_DATA == resourceType) {
            if (!isApiEnabled) {
                final NvdParser parser = new NvdParser(this::processVulnerability);
                parser.parse(uncompressedFile);
                Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
                Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, VulnerableSoftware.class));
            } else {
                LOGGER.debug("""
                        %s was successfully downloaded and uncompressed, but will not be parsed because \
                        mirroring via NVD REST API is enabled""".formatted(uncompressedFile.getName()));
            }
            // Update modification time
            File timestampFile = new File(file.getAbsolutePath() + ".ts");
            writeTimeStampFile(timestampFile, start);
        }
        final long end = System.currentTimeMillis();
        metricParseTime += end - start;
    }

    private void processVulnerability(final Vulnerability vuln, final List<VulnerableSoftware> vsList) {
        try (final var qm = new QueryManager().withL2CacheDisabled()) {
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");
            qm.getPersistenceManager().setProperty(PROPERTY_RETAIN_VALUES, "true");
            qm.getPersistenceManager().addInstanceLifecycleListener(new IndexingInstanceLifecycleListener(Event::dispatch),
                    Vulnerability.class, VulnerableSoftware.class);
            qm.getPersistenceManager().addInstanceLifecycleListener(new L2CacheEvictingInstanceLifecycleListener(qm),
                    AffectedVersionAttribution.class, Vulnerability.class, VulnerableSoftware.class);

            final Vulnerability persistentVuln = synchronizeVulnerability(qm, vuln);
            synchronizeVulnerableSoftware(qm, persistentVuln, vsList);
        } catch (RuntimeException e) {
            LOGGER.error("An unexpected error occurred while processing %s".formatted(vuln.getVulnId()), e);
        }
    }

    /**
     * Closes a closable object.
     * @param object the object to close
     */
    private void close(final Closeable object) {
        if (object != null) {
            try {
                object.close();
            } catch (IOException e) {
                LOGGER.warn("Error closing stream", e);
            }
        }
    }

    /**
     * Writes the modification time to a timestamp file
     * @param file the file
     * @param modificationTime the time of the last update
     */
    private void writeTimeStampFile(final File file, Long modificationTime)
    {
        FileWriter writer = null;
        try {
            writer= new FileWriter(file);
            writer.write(Long.toString(modificationTime));
        }
        catch (IOException ex) {
            LOGGER.error("An error occurred writing time stamp file", ex);
        }
        finally {
            close(writer);
        }
    }
}
