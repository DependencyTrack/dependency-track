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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpUriRequest;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.nvd.NvdParser;
import org.dependencytrack.persistence.QueryManager;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Calendar;
import java.util.Date;
import java.util.zip.GZIPInputStream;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_FEEDS_URL;

/**
 * Subscriber task that performs a mirror of the National Vulnerability Database.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class NistMirrorTask implements LoggableSubscriber {

    private enum ResourceType {
        CVE_YEAR_DATA,
        CVE_MODIFIED_DATA,
        CVE_META,
        CPE,
        CWE,
        NONE // DO NOT PARSE THIS TYPE
    }

    public static final String NVD_MIRROR_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "nist";
    private static final String CVE_JSON_11_MODIFIED_URL = "/json/cve/1.1/nvdcve-1.1-modified.json.gz";
    private static final String CVE_JSON_11_BASE_URL = "/json/cve/1.1/nvdcve-1.1-%d.json.gz";
    private static final String CVE_JSON_11_MODIFIED_META = "/json/cve/1.1/nvdcve-1.1-modified.meta";
    private static final String CVE_JSON_11_BASE_META = "/json/cve/1.1/nvdcve-1.1-%d.meta";
    private static final int START_YEAR = 2002;
    private final int endYear = Calendar.getInstance().get(Calendar.YEAR);

    private final boolean isEnabled;
    private String nvdFeedsUrl;
    private File outputDir;
    private long metricParseTime;
    private long metricDownloadTime;

    private static final Logger LOGGER = Logger.getLogger(NistMirrorTask.class);

    private boolean mirroredWithoutErrors = true;

    public NistMirrorTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_NVD_ENABLED.getGroupName(), VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyName());
            this.isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
            this.nvdFeedsUrl = qm.getConfigProperty(VULNERABILITY_SOURCE_NVD_FEEDS_URL.getGroupName(), VULNERABILITY_SOURCE_NVD_FEEDS_URL.getPropertyName()).getPropertyValue();
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
            final long start = System.currentTimeMillis();
            LOGGER.info("Starting NIST mirroring task");
            final File mirrorPath = new File(NVD_MIRROR_DIR);
            setOutputDir(mirrorPath.getAbsolutePath());
            getAllFiles();
            final long end = System.currentTimeMillis();
            LOGGER.info("NIST mirroring complete");
            LOGGER.info("Time spent (d/l):   " + metricDownloadTime + "ms");
            LOGGER.info("Time spent (parse): " + metricParseTime + "ms");
            LOGGER.info("Time spent (total): " + (end - start) + "ms");
            Event.dispatch(new EpssMirrorEvent());
        }
    }

    /**
     * Download all NVD XML and JSON feeds from NIST.
     */
    private void getAllFiles() {
        final Date currentDate = new Date();
        LOGGER.info("Downloading files at " + currentDate);
        doDownload(this.nvdFeedsUrl + CVE_JSON_11_MODIFIED_URL, ResourceType.CVE_MODIFIED_DATA);
        doDownload(this.nvdFeedsUrl + CVE_JSON_11_MODIFIED_META, ResourceType.CVE_META);
        for (int i = endYear; i >= START_YEAR; i--) {
            // Download JSON 1.1 year feeds in reverse order
            final String json11BaseUrl = this.nvdFeedsUrl + CVE_JSON_11_BASE_URL.replace("%d", String.valueOf(i));
            final String cve11BaseMetaUrl = this.nvdFeedsUrl + CVE_JSON_11_BASE_META.replace("%d", String.valueOf(i));
            doDownload(json11BaseUrl, ResourceType.CVE_YEAR_DATA);
            doDownload(cve11BaseMetaUrl, ResourceType.CVE_META);
        }

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
            final URL url = new URL(urlString);
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
            try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
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
        } catch (IOException e) {
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
            final NvdParser parser = new NvdParser();
            parser.parse(uncompressedFile);
            // Update modification time
            File timestampFile = new File(file.getAbsolutePath() + ".ts");
            writeTimeStampFile(timestampFile, start);
        }
        final long end = System.currentTimeMillis();
        metricParseTime += end - start;
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
