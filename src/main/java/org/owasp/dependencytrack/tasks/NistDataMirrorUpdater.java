/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) Axway. All Rights Reserved.
 */
package org.owasp.dependencytrack.tasks;

import org.apache.commons.io.IOUtils;
import org.owasp.dependencytrack.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Calendar;

/**
 * Performs a complete download of all NIST CVE data and provides access
 * to the sources via an internal mirror.
 * @author Steve Springett (steve.springett@owasp.org)
 */
public class NistDataMirrorUpdater {

    /**
     * NIST CVE 1.2 Modified URL (GZip feed)
     */
    private static final String CVE_12_MODIFIED_URL = "https://nvd.nist.gov/download/nvdcve-Modified.xml.gz";

    /**
     * NIST CVE 2.0 Modified URL (GZip feed)
     */
    private static final String CVE_20_MODIFIED_URL = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz";

    /**
     * NIST CVE 1.2 Base URL (GZip feed)
     */
    private static final String CVE_12_BASE_URL = "https://nvd.nist.gov/download/nvdcve-%d.xml.gz";

    /**
     * NIST CVE 2.0 Base URL (GZip feed)
     */
    private static final String CVE_20_BASE_URL = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz";

    /**
     * The year to begin mirroring from. NIST CVE data begins in 2002.
     */
    private static final int START_YEAR = 2002;

    /**
     * The year to end mirror of. Defaults to current year.
     */
    private static final int END_YEAR = Calendar.getInstance().get(Calendar.YEAR);

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NistDataMirrorUpdater.class);


    /**
     * Updates the NIST data directory.
     */
    @Scheduled(fixedRate = 86400000) // every 24 hours
    public void doUpdates() {
        try {
            doDownload(CVE_12_MODIFIED_URL);
            doDownload(CVE_20_MODIFIED_URL);
            for (int i = START_YEAR; i <= END_YEAR; i++) {
                final String cve12BaseUrl = CVE_12_BASE_URL.replace("%d", String.valueOf(i));
                final String cve20BaseUrl = CVE_20_BASE_URL.replace("%d", String.valueOf(i));
                doDownload(cve12BaseUrl);
                doDownload(cve20BaseUrl);
            }
        } catch (IOException e) {
            LOGGER.warn("An error occurred during the NIST data mirror update process: " + e.getMessage());
        }
    }

    /**
     * Perform a download of NIST data and save it to the nist data directory
     * @param cveUrl The url to download
     * @throws IOException if method encounters a problem downloading or saving the files
     */
    private void doDownload(String cveUrl) throws IOException {
        BufferedInputStream bis = null;
        BufferedOutputStream bos = null;

        try {
            final URL url = new URL(cveUrl);
            final URLConnection urlConnection = url.openConnection();
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Downloading " + url.toExternalForm());
            }

            String filename = url.getFile();
            filename = filename.substring(filename.lastIndexOf('/') + 1);

            bis = new BufferedInputStream(urlConnection.getInputStream());

            final File dir = new File(Constants.NIST_DIR);
            if (!dir.exists()) {
                dir.mkdir();
            }

            final File file = new File(Constants.NIST_DIR + File.separator + filename);
            bos = new BufferedOutputStream(new FileOutputStream(file));

            int i;
            while ((i = bis.read()) != -1) {
                bos.write(i);
            }
        } catch (IOException e) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("An error occurred during the download or saving of NIST XML data: " + e.getMessage());
            }
        } finally {
            IOUtils.closeQuietly(bis);
            IOUtils.closeQuietly(bos);
        }
    }

    /**
     * Performs exact match validation to ensure the specified filename matches a known NIST filename.
     * @param filename the filename to check
     * @return a boolean value
     */
    public static boolean isValidNistFile(String filename) {
        if (filename.equals(CVE_12_MODIFIED_URL.substring(CVE_12_MODIFIED_URL.lastIndexOf('/') + 1))
                || filename.equals(CVE_20_MODIFIED_URL.substring(CVE_20_MODIFIED_URL.lastIndexOf('/') + 1))) {
            return true;
        }
        for (int i = START_YEAR; i <= END_YEAR; i++) {
            final String cve12BaseUrl = CVE_12_BASE_URL.replace("%d", String.valueOf(i));
            final String cve20BaseUrl = CVE_20_BASE_URL.replace("%d", String.valueOf(i));

            if (filename.equals(cve12BaseUrl.substring(cve12BaseUrl.lastIndexOf('/') + 1))
                    || filename.equals(cve20BaseUrl.substring(cve20BaseUrl.lastIndexOf('/') + 1))) {
                return true;
            }
        }
        return false;
    }
}
