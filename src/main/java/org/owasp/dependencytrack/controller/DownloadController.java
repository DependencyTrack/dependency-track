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
package org.owasp.dependencytrack.controller;

import org.apache.commons.io.IOUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.owasp.dependencytrack.tasks.NistDataMirrorUpdater;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletResponse;
import java.io.*;

/**
 * Controller logic for all download-related requests.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Controller
public class DownloadController extends AbstractController {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DownloadController.class);

    @Value("${app.nist.dir}")
    private String nistDir;

    @Value("${app.data.path}")
    private String appDataPath;

    @Value("${app.data.file}")
    private String appDataFile;

    /**
     * Service to download the Dependency-Check datafile archive.
     *
     * @param response an HttpServletResponse object
     */
    @RequiresPermissions("dcdata")
    @RequestMapping(value = "/dcdata", method = RequestMethod.GET)
    public void getDataMirrorFile(HttpServletResponse response) {
        InputStream fis = null;
        OutputStream out = null;
        try {
            fis = new FileInputStream(appDataPath);
            response.setHeader("Content-Disposition", "inline;filename=\"" + appDataFile + "\"");
            response.setHeader("Content-Type", "application/octet-stream;");
            out = response.getOutputStream();
            IOUtils.copy(fis, out);
            out.flush();
        } catch (IOException ex) {
            LOGGER.info("Error writing Dependency-Check datafile to output stream.");
            throw new RuntimeException("IOError writing file to output stream");
        } finally {
            IOUtils.closeQuietly(out);
            IOUtils.closeQuietly(fis);
        }
    }

    /**
     * Service to download NIST CPE/CVE XML data files.
     *
     * @param response an HttpServletResponse object
     * @param filename the xml file to download
     * @throws java.io.IOException bad robot
     */
    @RequestMapping(value = "/nist/{filename:.+}", method = {RequestMethod.GET, RequestMethod.HEAD})
    public void getNistFile(HttpServletResponse response,
                            @PathVariable("filename") String filename) throws IOException {
        final File canonicalizedFile = new File(filename).getCanonicalFile();
        if (!NistDataMirrorUpdater.isValidNistFile(canonicalizedFile.getName())) {
            response.sendError(404);
        }
        InputStream fis = null;
        OutputStream out = null;
        try {
            File file = new File(nistDir + File.separator + filename);
            fis = new FileInputStream(file);
            if (filename.endsWith(".gz")) {
                response.setHeader("Content-Type", "application/x-gzip;");
            } else if (filename.endsWith(".xml")) {
                response.setHeader("Content-Type", "application/xml;");
            }
            response.addDateHeader("Last-Modified", file.lastModified());
            out = response.getOutputStream();
            IOUtils.copy(fis, out);
            out.flush();
        } catch (IOException ex) {
            LOGGER.error("Error writing NIST datafile to output stream.");
            throw new RuntimeException("IOError writing file to output stream");
        } finally {
            IOUtils.closeQuietly(out);
            IOUtils.closeQuietly(fis);
        }
    }

}
