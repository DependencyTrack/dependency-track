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
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.epss.EpssParser;
import org.dependencytrack.persistence.QueryManager;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.util.zip.GZIPInputStream;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_EPSS_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_EPSS_FEEDS_URL;

public class EpssMirrorTask implements LoggableSubscriber {

    public static final String MIRROR_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "first";
    private static final String FILENAME = "epss_scores-current.csv.gz";
    private static final Logger LOGGER = Logger.getLogger(EpssMirrorTask.class);

    private final boolean isEnabled;
    private String feedUrl;
    private File outputDir;
    private long metricParseTime;
    private long metricDownloadTime;
    private boolean mirroredWithoutErrors = true;

    public EpssMirrorTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_EPSS_ENABLED.getGroupName(), VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyName());
            this.isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
            this.feedUrl = qm.getConfigProperty(VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getGroupName(), VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyName()).getPropertyValue();
            if (this.feedUrl.endsWith("/")) {
                this.feedUrl = this.feedUrl.substring(0, this.feedUrl.length()-1);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof EpssMirrorEvent && this.isEnabled) {
            final long start = System.currentTimeMillis();
            LOGGER.info("Starting EPSS mirroring task");
            final File mirrorPath = new File(MIRROR_DIR);
            setOutputDir(mirrorPath.getAbsolutePath());
            getAllFiles();
            final long end = System.currentTimeMillis();
            LOGGER.info("EPSS mirroring complete");
            LOGGER.info("Time spent (d/l):   " + metricDownloadTime + "ms");
            LOGGER.info("Time spent (parse): " + metricParseTime + "ms");
            LOGGER.info("Time spent (total): " + (end - start) + "ms");
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
     * Download all EPSS files
     */
    private void getAllFiles() {
        doDownload(this.feedUrl + "/" + FILENAME);
        if (mirroredWithoutErrors) {
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.DATASOURCE_MIRRORING)
                    .title(NotificationConstants.Title.EPSS_MIRROR)
                    .content("Mirroring of the Exploit Prediction Scoring System completed successfully")
                    .level(NotificationLevel.INFORMATIONAL)
            );
        }
    }

    /**
     * Performs a download of specified URL.
     * @param urlString the URL contents to download
     */
    private void doDownload(final String urlString) {
        File file;
        try {
            final URL url = new URL(urlString);
            String filename = url.getFile();
            filename = filename.substring(filename.lastIndexOf('/') + 1);
            file = new File(outputDir, filename).getAbsoluteFile();
            if (file.exists()) {
                // Update EPSS scores every other day
                if (System.currentTimeMillis() < ((86400000 * 2) + file.lastModified())) {
                    LOGGER.info("Retrieval of " + filename + " not necessary.");
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
                if (status.getStatusCode() == HttpStatus.SC_OK) {
                    LOGGER.info("Downloading...");
                    try (InputStream in = response.getEntity().getContent()) {
                        file = new File(outputDir, filename);
                        FileUtils.copyInputStreamToFile(in, file);
                        // Sets the last modified date to 0. Upon a successful parse, it will be set back to its original date.
                        file.setLastModified(0);
                        if (file.getName().endsWith(".gz")) {
                            uncompress(file);
                        }
                    }
                } else {
                    mirroredWithoutErrors = false;
                    LOGGER.warn("Unable to download - HTTP Response " + status.getStatusCode() + ": " + status.getReasonPhrase());
                    Notification.dispatch(new Notification()
                            .scope(NotificationScope.SYSTEM)
                            .group(NotificationGroup.DATASOURCE_MIRRORING)
                            .title(NotificationConstants.Title.EPSS_MIRROR)
                            .content("An error occurred mirroring the contents of the Exploit Prediction Scoring System. Check log for details. HTTP Response: " + status.getStatusCode())
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
                    .title(NotificationConstants.Title.EPSS_MIRROR)
                    .content("An error occurred mirroring the contents of the Exploit Prediction Scoring System. Check log for details. " + e.getMessage())
                    .level(NotificationLevel.ERROR)
            );
        }
    }

    /**
     * Extracts a GZip file.
     * @param file the file to extract
     */
    private void uncompress(final File file) {
        final byte[] buffer = new byte[1024];
        GZIPInputStream gzis = null;
        OutputStream out = null;
        try {
            LOGGER.info("Uncompressing " + file.getName());
            gzis = new GZIPInputStream(Files.newInputStream(file.toPath()));
            final File uncompressedFile = new File(file.getAbsolutePath().replaceAll(".gz", ""));
            out = Files.newOutputStream(uncompressedFile.toPath());
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                out.write(buffer, 0, len);
            }
            final long start = System.currentTimeMillis();
            final EpssParser parser = new EpssParser();
            parser.parse(uncompressedFile);
            file.setLastModified(start);
            final long end = System.currentTimeMillis();
            metricParseTime += end - start;
        } catch (IOException ex) {
            mirroredWithoutErrors = false;
            LOGGER.error("An error occurred uncompressing EPSS payload", ex);
        } finally {
            close(gzis);
            close(out);
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
