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
import org.owasp.dependencytrack.model.LibraryVendor;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.service.LibraryVersionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

/**
 * Controller logic for all Library-related requests.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Controller
public class LibraryController extends AbstractController {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LibraryController.class);

    /**
     * The Dependency-Track LibraryVersionService.
     */
    @Autowired
    private LibraryVersionService libraryVersionService;


    /**
     * Updates a library regardless of application association.
     *
     * @param vendorid         The ID of the LibraryVendor
     * @param licenseid        The ID of the License
     * @param libraryid        The ID of the Library
     * @param libraryversionid The ID of the LibraryVersion
     * @param libraryname      The name of the Library
     * @param libraryversion   The version label of the Library
     * @param vendor           The String representation of the Vendor
     * @param license          The license the Library is licensed under
     * @param language         The programming language the Library was written in
     * @return a String
     */
    @RequiresPermissions("updatelibrary")
    @RequestMapping(value = "/updatelibrary", method = RequestMethod.POST)
    public String updatingLibrary(@RequestParam("editvendorid") int vendorid,
                                  @RequestParam("editlicenseid") int licenseid,
                                  @RequestParam("editlibraryid") int libraryid,
                                  @RequestParam("editlibraryversionid") int libraryversionid,
                                  @RequestParam("libraryname") String libraryname,
                                  @RequestParam("libraryversion") String libraryversion,
                                  @RequestParam("vendor") String vendor,
                                  @RequestParam("license") String license,
                                  @RequestParam("language") String language) {

        libraryVersionService.updateLibrary(vendorid, licenseid, libraryid,
                libraryversionid, libraryname, libraryversion, vendor, license, language);
        return "redirect:/libraries";
    }

    /**
     * Remove the libraryVersion with the specified ID.
     *
     * @param libraryversionid The LibraryVersion ID
     * @return a String
     */
    @RequiresPermissions("removelibrary")
    @RequestMapping(value = "/removelibrary/{libraryversionid}", method = RequestMethod.GET)
    public String removeLibrary(@PathVariable("libraryversionid") Integer libraryversionid) {
        libraryVersionService.removeLibrary(libraryversionid);
        return "redirect:/libraries";
    }

    /**
     * Returns a list of all libraries regardless of application association.
     *
     * @param map a map of parameters
     * @return a String
     */
    @RequiresPermissions("libraries")
    @RequestMapping(value = "/libraries", method = RequestMethod.GET)
    public String allLibrary(Map<String, Object> map) {
        map.put("LibraryVersion", new LibraryVersion());
        map.put("libList", libraryVersionService.allLibrary());
        map.put("uniquelibList", libraryVersionService.uniqueLibrary());
        map.put("uniquelicList", libraryVersionService.uniqueLicense());
        map.put("uniquevenList", libraryVersionService.uniqueVendor());
        map.put("uniqueLang", libraryVersionService.uniqueLang());
        map.put("uniqueVer", libraryVersionService.uniqueVer());
        return "librariesPage";
    }

    /**
     * Adds a library regardless of application association.
     *
     * @param libraryname    The name of the Library
     * @param libraryversion The version of the Library
     * @param vendor         The vendor of the Library
     * @param license        The license the Library is licensed under
     * @param file           The license file
     * @param language       The programming language the Library was written in
     * @return a String
     */
    @RequiresPermissions("addlibraries")
    @RequestMapping(value = "/addlibraries", method = RequestMethod.POST)
    public String addLibraries(@RequestParam("libnamesel") String libraryname,
                               @RequestParam("libversel") String libraryversion,
                               @RequestParam("vendorsel") String vendor,
                               @RequestParam("licensesel") String license,
                               @RequestParam("Licensefile") MultipartFile file,
                               @RequestParam("languagesel") String language) {

        libraryVersionService.addLibraries(libraryname, libraryversion, vendor, license, file, language);
        return "redirect:/libraries";
    }

    /**
     * Download license action.
     *
     * @param response  a Response object
     * @param licenseid the ID of the License to download
     */
    @RequiresPermissions("downloadlicense")
    @RequestMapping(value = "/downloadlicense", method = RequestMethod.POST)
    public void downloadLicense(HttpServletResponse response,
                                @RequestParam("licenseid") Integer licenseid) {

        final List<License> licenses = libraryVersionService.listLicense(licenseid);
        final License newLicense = licenses.get(0);

        InputStream in = null;
        OutputStream out = null;
        try {
            response.setHeader("Content-Disposition", "inline;filename=\"" + newLicense.getFilename() + "\"");
            response.setHeader("Content-Type", "application/octet-stream;");
            in = newLicense.getText().getBinaryStream();
            out = response.getOutputStream();
            IOUtils.copy(in, out);
            out.flush();
        } catch (IOException | SQLException e) {
            LOGGER.error("An error occurred downloading a license");
            LOGGER.error(e.getMessage());
        } finally {
            IOUtils.closeQuietly(in);
            IOUtils.closeQuietly(out);
        }

    }

    /**
     * View license action.
     *
     * @param response  a Response object
     * @param licenseid the ID of the License to download
     * @return a String
     */
    @RequiresPermissions("viewlicense")
    @RequestMapping(value = "/viewlicense/{licenseid}", method = RequestMethod.GET)
    public String viewLicense(HttpServletResponse response,
                              @PathVariable("licenseid") Integer licenseid) {

        final List<License> licenses = libraryVersionService.listLicense(licenseid);
        final License newLicense = licenses.get(0);
        if ("text/plain".equals(newLicense.getContenttype()) || "text/html".equals(newLicense.getContenttype())) {

            InputStream in = null;
            OutputStream out = null;
            try {
                response.setHeader("Content-Disposition", "inline;filename=\"" + newLicense.getFilename() + "\"");
                in = newLicense.getText().getBinaryStream();
                out = response.getOutputStream();
                response.setContentType(newLicense.getContenttype());
                IOUtils.copy(in, out);
                out.flush();
            } catch (IOException | SQLException e) {
                LOGGER.error("An error occurred while viewing a license");
                LOGGER.error(e.getMessage());
            } finally {
                IOUtils.closeQuietly(in);
                IOUtils.closeQuietly(out);
            }
        } else {
            return "emptyfile";
        }
        return "";
    }

    /**
     * Returns a json list of the complete Library Hierarchy.
     *
     * @param map a map of parameters
     * @return a String
     */
    //  @RequiresPermissions("libraryHierarchy")
    @RequestMapping(value = "/libraryHierarchy", method = RequestMethod.GET)
    @ResponseBody
    public List<LibraryVendor> getLibraryHierarchy(Map<String, Object> map) {
        return libraryVersionService.getLibraryHierarchy();

    }

}
