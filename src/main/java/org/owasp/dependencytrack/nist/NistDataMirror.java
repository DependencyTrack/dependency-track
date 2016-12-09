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
package org.owasp.dependencytrack.nist;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencytrack.Config;
import org.owasp.dependencytrack.logging.Logger;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.Calendar;
import java.util.Date;
import java.util.zip.GZIPInputStream;

public class NistDataMirror {

    private static final String CVE_12_MODIFIED_URL = "https://nvd.nist.gov/download/nvdcve-Modified.xml.gz";
    private static final String CVE_20_MODIFIED_URL = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz";
    private static final String CVE_12_BASE_URL = "https://nvd.nist.gov/download/nvdcve-%d.xml.gz";
    private static final String CVE_20_BASE_URL = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz";
    private static final int START_YEAR = 2002;
    private static final int END_YEAR = Calendar.getInstance().get(Calendar.YEAR);
    private File outputDir;
    private static boolean downloadFailed = false;

    private static final Logger logger = Logger.getLogger(NistDataMirror.class);

    public boolean doUpdates(File outputDirectory) {
        setOutputDir(outputDirectory.getAbsolutePath());
        getAllFiles();
        return !downloadFailed;
    }

    private void getAllFiles() {
        Date currentDate = new Date();
        logger.info("Downloading files at " + currentDate);

        doDownload(CVE_12_MODIFIED_URL);
        doDownload(CVE_20_MODIFIED_URL);
        for (int i=START_YEAR; i<=END_YEAR; i++) {
            String cve12BaseUrl = CVE_12_BASE_URL.replace("%d", String.valueOf(i));
            String cve20BaseUrl = CVE_20_BASE_URL.replace("%d", String.valueOf(i));
            doDownload(cve12BaseUrl);
            doDownload(cve20BaseUrl);
        }
    }

    private void setOutputDir(String outputDirPath) {
        outputDir = new File(outputDirPath);
        if ( ! outputDir.exists()) {
            outputDir.mkdirs();
        }
    }

    private long checkHead(String cveUrl) {
        try {
            URL url = new URL(cveUrl);
            HttpURLConnection connection = (HttpURLConnection)url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.connect();
            connection.getInputStream();
            return connection.getContentLengthLong();
        } catch (IOException e) {
            logger.error("Failed to determine content length");
        }
        return 0;
    }

    private void doDownload(String cveUrl) {
        BufferedInputStream bis = null;
        BufferedOutputStream bos = null;
        File file = null;
        boolean success = false;

        Proxy proxy = Proxy.NO_PROXY;
        final String proxyAddr = Config.getInstance().getProperty(Config.Key.HTTP_PROXY_ADDRESS);
        if (StringUtils.isNotBlank(proxyAddr)) {
            final Integer proxyPort = Config.getInstance().getPropertyAsInt(Config.Key.HTTP_PROXY_PORT);
            proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyAddr, proxyPort));
        }

        try {
            URL url = new URL(cveUrl);
            String filename = url.getFile();
            filename = filename.substring(filename.lastIndexOf('/') + 1);
            file = new File(outputDir, filename).getAbsoluteFile();

            if (file.exists()) {
                long fileSize = checkHead(cveUrl);
                if (file.length() == fileSize) {
                    logger.info("Using cached version of " + filename);
                    return;
                }
            }

            URLConnection connection = url.openConnection(proxy);
            logger.info("Downloading " + url.toExternalForm());
            bis = new BufferedInputStream(connection.getInputStream());
            file = new File(outputDir, filename);
            bos = new BufferedOutputStream(new FileOutputStream(file));

            int i;
            while ((i = bis.read()) != -1) {
                bos.write(i);
            }
            success = true;
        } catch (IOException e) {
            logger.error("Download failed : " + e.getLocalizedMessage());
            downloadFailed = true;
        } finally {
            close(bis);
            close(bos);
        }
        if (file != null && success)
            uncompress(file);
    }

    private void uncompress(File file) {
        byte[] buffer = new byte[1024];
        GZIPInputStream gzis = null;
        FileOutputStream out = null;
        try{
            logger.info("Uncompressing " + file.getName());
            gzis = new GZIPInputStream(new FileInputStream(file));
            out = new FileOutputStream(new File(file.getAbsolutePath().replaceAll(".gz", "")));
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                out.write(buffer, 0, len);
            }
        }catch(IOException ex){
            ex.printStackTrace();
        } finally {
            close(gzis);
            close(out);
        }
    }

    private void close (Closeable object) {
        if (object != null) {
            try {
                object.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
