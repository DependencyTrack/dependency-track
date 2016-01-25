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
 */
package org.owasp.dependencytrack.tasks;

import org.apache.commons.io.IOUtils;
import org.joda.time.LocalDateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;

import javax.annotation.PostConstruct;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Calendar;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Performs a complete download of all NIST CVE data and provides access
 * to the sources via an internal mirror.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public class NistDataMirrorUpdater implements ApplicationListener<NistDataMirrorUpdateRequestedEvent> {

    private static Pattern validFileNamePattern = Pattern.compile("nvdcve(-\\d\\.\\d)?(-Modified)?(-\\d{4})?\\.xml\\.gz");

    /**
     * The last time a download successfully occurred
     */
    LocalDateTime lastDownload = null;

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
    private static final String CVE_12_BASE_URL = "https://nvd.nist.gov/download/nvdcve-{year}.xml.gz";

    /**
     * NIST CVE 2.0 Base URL (GZip feed)
     */
    private static final String CVE_20_BASE_URL = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-{year}.xml.gz";

    /**
     * The year to begin mirroring from. NIST CVE data begins in 2002.
     */
    private static final int START_YEAR = 2002;

    /**
     * The year to end mirror of. Defaults to current year.
     */
    private static int END_YEAR = Calendar.getInstance().get(Calendar.YEAR);

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NistDataMirrorUpdater.class);

    private String nistDir;
    private Set<URL> downloadURLS;

    public NistDataMirrorUpdater(String nistDir) {
        this.nistDir = nistDir;
    }

    @PostConstruct
    public void initUpdater() {
        initialiseUrls();
        final File dir = new File(nistDir);
        if (!dir.exists()) {
            dir.mkdir();
        } else {
            lastDownload = getLatestDownloadDate();
        }
    }

    private LocalDateTime getLatestDownloadDate() {
        LocalDateTime latest = null;
        for (URL url : downloadURLS) {
            File localFile = getLocalFileFor(url);
            if (!localFile.exists() || localFile.length()==0 ){
                return null; // if any files don't exist we need to reload em all.
            }
            latest = new LocalDateTime(localFile.lastModified());
        }
        return latest;
    }

    private File getLocalFileFor(URL url) {
        return new File(getFilenameFromURL(url));
    }

    private void initialiseUrls() {
        downloadURLS = new LinkedHashSet<>();
        try {
            downloadURLS.add(new URL(CVE_12_MODIFIED_URL));
            downloadURLS.add(new URL(CVE_20_MODIFIED_URL));

            for (int year = START_YEAR; year <= END_YEAR; year++) {
                downloadURLS.add(new URL(fillInYearValue(CVE_12_BASE_URL, year)));
                downloadURLS.add(new URL(fillInYearValue(CVE_20_BASE_URL, year)));
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Updates the NIST data directory.
     * @param endYear
     * @param now
     */
    public void doUpdates(int endYear, LocalDateTime now) {
        try {
            int previousEndYear = END_YEAR;
            boolean newYearAdded = false;

            END_YEAR = endYear;
            if(END_YEAR!=previousEndYear){
                newYearAdded=true;
                downloadURLS.add(new URL(fillInYearValue(CVE_12_BASE_URL, END_YEAR)));
                downloadURLS.add(new URL(fillInYearValue(CVE_20_BASE_URL, END_YEAR)));
            }

            if((newYearAdded)
                    ||(lastDownload==null)
                    ||(now.compareTo(lastDownload.plusHours(2)) > 1)){
                for (URL url : downloadURLS) {
                    doDownload(url);
                }
            }
        } catch (IOException e) {
            LOGGER.warn("An error occurred during the NIST data mirror update process: " + e.getMessage());
        }
    }

    /**
     * Perform a download of NIST data and save it to the nist data directory
     *
     * @param cveUrl The url to download
     * @throws IOException if method encounters a problem downloading or saving the files
     */
    private void doDownload(URL cveUrl) throws IOException {
        BufferedInputStream bis = null;
        BufferedOutputStream bos = null;

        try {
            final URL url = cveUrl;
            final URLConnection urlConnection = url.openConnection();
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Downloading " + url.toExternalForm());
            }

            String filename = url.getFile();
            filename = filename.substring(filename.lastIndexOf('/') + 1);

            bis = new BufferedInputStream(urlConnection.getInputStream());

            final File file = getLocalFile(filename);
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

    private File getLocalFile(String filename) {
        return new File(nistDir + File.separator + filename);
    }

    /**
     * Performs exact match validation to ensure the specified filename matches a known NIST filename.
     *
     * @param filename the filename to check
     * @return a boolean value
     */
    public static boolean isValidNistFile(String filename) {

        return validFileNamePattern.matcher(filename).matches();
    }

    public static String fillInYearValue(String pattern, int year) {
        return pattern.replace("{year}", String.valueOf(year));
    }

    public static String getFilenameFromURL(URL url) {
        return getFilenameFromURL(url.getPath());
    }

    public static String getFilenameFromURL(String url) {
        int index = url.lastIndexOf('/');
        index = index != -1 ? index + 1 : 0;
        return url.substring(index);
    }

    @Override
    public void onApplicationEvent(NistDataMirrorUpdateRequestedEvent event) {
        doUpdates(Calendar.getInstance().get(Calendar.YEAR), LocalDateTime.now());
    }
}
