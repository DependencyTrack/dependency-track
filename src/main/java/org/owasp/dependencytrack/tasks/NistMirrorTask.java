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

import alpine.Config;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencytrack.event.NistMirrorEvent;
import org.owasp.dependencytrack.parser.nvd.NvdParser;
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

public class NistMirrorTask implements Subscriber {

    private static final String CVE_XML_12_MODIFIED_URL = "https://nvd.nist.gov/download/nvdcve-Modified.xml.gz";
    private static final String CVE_XML_20_MODIFIED_URL = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz";
    private static final String CVE_XML_12_BASE_URL = "https://nvd.nist.gov/download/nvdcve-%d.xml.gz";
    private static final String CVE_XML_20_BASE_URL = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz";
    private static final String CVE_JSON_10_MODIFIED_URL = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz";
    private static final String CVE_JSON_10_BASE_URL = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.json.gz";
    private static final int START_YEAR = 2002;
    private static final int END_YEAR = Calendar.getInstance().get(Calendar.YEAR);
    private File outputDir;

    private static final Logger LOGGER = Logger.getLogger(NistMirrorTask.class);


    public void inform(Event e) {
        if (e instanceof NistMirrorEvent) {
            LOGGER.info("Starting NIST mirroring task");
            final File mirrorPath = new File(Config.getInstance().getDataDirectorty(), "nist");
            setOutputDir(mirrorPath.getAbsolutePath());
            getAllFiles();
            LOGGER.info("NIST mirroring complete");
        }
    }

    private void getAllFiles() {
        final Date currentDate = new Date();
        LOGGER.info("Downloading files at " + currentDate);
        for (int i = START_YEAR; i <= END_YEAR; i++) {
            final String xml12BaseUrl = CVE_XML_12_BASE_URL.replace("%d", String.valueOf(i));
            final String xml20BaseUrl = CVE_XML_20_BASE_URL.replace("%d", String.valueOf(i));
            final String json10BaseUrl = CVE_JSON_10_BASE_URL.replace("%d", String.valueOf(i));
            doDownload(xml12BaseUrl);
            doDownload(xml20BaseUrl);
            doDownload(json10BaseUrl);
        }
        doDownload(CVE_XML_12_MODIFIED_URL);
        doDownload(CVE_XML_20_MODIFIED_URL);
        doDownload(CVE_JSON_10_MODIFIED_URL);
    }

    private void setOutputDir(String outputDirPath) {
        outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }
    }

    private long checkHead(String cveUrl) {
        try {
            final URL url = new URL(cveUrl);
            final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.connect();
            connection.getInputStream();
            return connection.getContentLengthLong();
        } catch (IOException e) {
            LOGGER.error("Failed to determine content length");
        }
        return 0;
    }

    private void doDownload(String cveUrl) {
        BufferedInputStream bis = null;
        BufferedOutputStream bos = null;
        File file = null;
        boolean success = false;

        Proxy proxy = Proxy.NO_PROXY;
        final String proxyAddr = Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_ADDRESS);
        if (StringUtils.isNotBlank(proxyAddr)) {
            final Integer proxyPort = Config.getInstance().getPropertyAsInt(Config.AlpineKey.HTTP_PROXY_PORT);
            proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyAddr, proxyPort));
        }

        try {
            final URL url = new URL(cveUrl);
            String filename = url.getFile();
            filename = filename.substring(filename.lastIndexOf('/') + 1);
            file = new File(outputDir, filename).getAbsoluteFile();

            if (file.exists()) {
                final long fileSize = checkHead(cveUrl);
                if (file.length() == fileSize) {
                    LOGGER.info("Using cached version of " + filename);
                    return;
                }
            }

            final URLConnection connection = url.openConnection(proxy);
            LOGGER.info("Downloading " + url.toExternalForm());
            bis = new BufferedInputStream(connection.getInputStream());
            file = new File(outputDir, filename);
            bos = new BufferedOutputStream(new FileOutputStream(file));

            int i;
            while ((i = bis.read()) != -1) {
                bos.write(i);
            }
            success = true;
        } catch (IOException e) {
            LOGGER.error("Download failed : " + e.getLocalizedMessage());
        } finally {
            close(bis);
            close(bos);
        }
        if (file != null && success) {
            uncompress(file);
        }
    }

    private void uncompress(File file) {
        final byte[] buffer = new byte[1024];
        GZIPInputStream gzis = null;
        FileOutputStream out = null;
        try {
            LOGGER.info("Uncompressing " + file.getName());
            gzis = new GZIPInputStream(new FileInputStream(file));
            final File uncompressedFile = new File(file.getAbsolutePath().replaceAll(".gz", ""));
            out = new FileOutputStream(uncompressedFile);
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                out.write(buffer, 0, len);
            }
            final NvdParser parser = new NvdParser();
            parser.parse(uncompressedFile);
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            close(gzis);
            close(out);
        }
    }

    private void close(Closeable object) {
        if (object != null) {
            try {
                object.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
