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
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpUriRequest;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.nvd.CpeDictionaryParser;
import org.dependencytrack.parser.nvd.NvdParser;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.util.Calendar;
import java.util.Date;
import java.util.zip.GZIPInputStream;

/**
 * Subscriber task that performs a mirror of the National Vulnerability Database.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class NistMirrorTask implements LoggableSubscriber {

    private enum ResourceType {
        CVE,
        CPE,
        CWE,
        NONE // DO NOT PARSE THIS TYPE
    }

    public static final String NVD_MIRROR_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "nist";
    private static final String CPE_DICTIONARY_23_XML = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz";
    private static final String CVE_JSON_11_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";
    private static final String CVE_JSON_11_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz";
    private static final String CVE_JSON_11_MODIFIED_META = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta";
    private static final String CVE_JSON_11_BASE_META = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.meta";
    private static final int START_YEAR = 2002;
    private static final int END_YEAR = Calendar.getInstance().get(Calendar.YEAR);
    private File outputDir;
    private long metricParseTime;
    private long metricDownloadTime;

    private static final Logger LOGGER = Logger.getLogger(NistMirrorTask.class);

    private boolean mirroredWithoutErrors = true;

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof NistMirrorEvent) {
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
        }
    }

    /**
     * Download all NVD XML and JSON feeds from NIST.
     */
    private void getAllFiles() {
        final Date currentDate = new Date();
        LOGGER.info("Downloading files at " + currentDate);
        // Download the CPE dictionary first
        doDownload(CPE_DICTIONARY_23_XML, ResourceType.CPE);
        for (int i = START_YEAR; i <= END_YEAR; i++) {
            // Download JSON 1.0 year feeds
            final String json10BaseUrl = CVE_JSON_11_BASE_URL.replace("%d", String.valueOf(i));
            final String cveBaseMetaUrl = CVE_JSON_11_BASE_META.replace("%d", String.valueOf(i));
            doDownload(json10BaseUrl, ResourceType.CVE);
            doDownload(cveBaseMetaUrl, ResourceType.CVE);
            // Download JSON 1.1 year feeds
            final String json11BaseUrl = CVE_JSON_11_BASE_URL.replace("%d", String.valueOf(i));
            final String cve11BaseMetaUrl = CVE_JSON_11_BASE_META.replace("%d", String.valueOf(i));
            doDownload(json11BaseUrl, ResourceType.NONE);
            doDownload(cve11BaseMetaUrl, ResourceType.NONE);
        }
        doDownload(CVE_JSON_11_MODIFIED_URL, ResourceType.CVE);
        doDownload(CVE_JSON_11_MODIFIED_META, ResourceType.CVE);

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
                final long fileSize = checkHead(urlString);
                if (file.length() == fileSize) {
                    LOGGER.info("Using cached version of " + filename);
                    return;
                }
            }
            final long start = System.currentTimeMillis();
            LOGGER.info("Initiating download of " + url.toExternalForm());
            final HttpUriRequest request = new HttpGet(urlString);
            try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                final StatusLine status = response.getStatusLine();
                final long end = System.currentTimeMillis();
                metricDownloadTime += end - start;
                if (status.getStatusCode() == 200) {
                    LOGGER.info("Downloading...");
                    try (InputStream in = response.getEntity().getContent()) {
                        file = new File(outputDir, filename);
                        FileUtils.copyInputStreamToFile(in, file);
                        if (file.getName().endsWith(".gz")) {
                            uncompress(file, resourceType);
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
}
