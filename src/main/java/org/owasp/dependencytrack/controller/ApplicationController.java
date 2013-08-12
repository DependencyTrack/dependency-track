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

package org.owasp.dependencytrack.controller;

import org.apache.commons.io.IOUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.service.ApplicationService;
import org.owasp.dependencytrack.service.ApplicationVersionService;
import org.owasp.dependencytrack.service.LibraryVersionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

@Controller
public class ApplicationController {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ApplicationController.class);

    /**
     * The Dependency-Track ApplicationService.
     */
    @Autowired
    private ApplicationService applicationService;

    /**
     * The Dependency-Track ApplicationVersionService.
     */
    @Autowired
    private ApplicationVersionService applicationVersionService;

    /**
     * The Dependency-Track LibraryVersionService.
     */
    @Autowired
    private LibraryVersionService libraryVersionService;

    /**
     * Initialization method gets called after controller is constructed.
     */
    @PostConstruct
    public void init() {
        LOGGER.info("OWASP Dependency-Track Initialized");
    }

    /**
     * Login action.
     * @param username The username to login with
     * @param passwd The password to login with
     * @param modelMap The Spring ModelMap
     * @return A String
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String loginchk(@RequestParam("username") String username,
                           @RequestParam("password") String passwd, ModelMap modelMap) {

        final UsernamePasswordToken token = new UsernamePasswordToken(username, passwd);
        try {
            SecurityUtils.getSubject().login(token);
        } catch (AuthenticationException e) {

        }
        return "redirect:/login";

    }

    /**
     * Login action.
     * @param modelMap The Spring ModelMap
     * @return a String
     */
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(ModelMap modelMap) {
        String s = "login";
        if (SecurityUtils.getSubject().isAuthenticated()) {
            s = "redirect:/home";
        }
        return s;
    }

    /**
     * Logout action.
     * @param modelMap The Spring ModelMap
     * @return a String
     */
    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout(ModelMap modelMap) {
        SecurityUtils.getSubject().logout();
        return "redirect:/login";
    }

    /**
     * Default page action.
     * @return a String
     */
    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String application() {
        return "redirect:/applications";
    }

    /**
     * Lists all applications.
     * @param map A map of parameters
     * @return a String
     */
    @RequestMapping(value = "/applications", method = RequestMethod.GET)
    public String application(Map<String, Object> map) {
        map.put("check", false);
        map.put("application", new Application());
        map.put("applicationList", applicationService.listApplications());
        return "applicationsPage";
    }

    /**
     * Search action.
     * @param map a map of parameters
     * @param libid the ID of the Library to search on
     * @param libverid The ID of the LibraryVersion to search on
     * @return a String
     */
    @RequestMapping(value = "/searchApplication", method = RequestMethod.POST)
    public String searchApplication(Map<String, Object> map, @RequestParam("serapplib") int libid,
                                    @RequestParam("serapplibver") int libverid) {

        if (libverid != -1) {
            map.put("applicationList", applicationService.searchApplications(libverid));
            map.put("versionlist", applicationService.searchApplicationsVersion(libverid));
            map.put("check", true);
        } else {

            map.put("applicationList", applicationService.searchAllApplications(libid));
            map.put("versionlist", applicationService.searchAllApplicationsVersions(libid));
            map.put("check", true);
        }
        return "applicationsPage";
    }

    /**
     * Add Application action. Adds an application and associated version number
     * @param application The Application to add
     * @param result a BindingResult
     * @param version a String of the version number to add
     * @return a String
     */
    @RequestMapping(value = "/addApplication", method = RequestMethod.POST)
    public String addApplication(@ModelAttribute("application") Application application,
                                 BindingResult result, @RequestParam("version") String version) {
        applicationService.addApplication(application, version);
        return "redirect:/applications";
    }

    /**
     * Updates an applications' name.
     * @param id The ID of the application to update
     * @param name The updated name of the application
     * @return a String
     */
    @RequestMapping(value = "/updateApplication", method = RequestMethod.POST)
    public String updatingProduct(@RequestParam("id") int id, @RequestParam("name") String name) {
        applicationService.updateApplication(id, name);
        return "redirect:/applications";
    }

    /**
     * Updates an applications' version.
     * @param id The ID of the ApplicationVersion
     * @param appversion The version label
     * @return a String
     */
    @RequestMapping(value = "/updateApplicationVersion", method = RequestMethod.POST)
    public String updatingApplicationVersion(@RequestParam("appversionid") int id,
                                             @RequestParam("editappver") String appversion) {
        applicationVersionService.updateApplicationVersion(id, appversion);
        return "redirect:/applications";
    }

    /**
     * Deletes the application with the specified id.
     * @param id The ID of the Application to delete
     * @return a String
     */
    @RequestMapping(value = "/deleteApplication/{id}", method = RequestMethod.GET)
    public String removeApplication(@PathVariable("id") int id) {
        applicationService.deleteApplication(id);
        return "redirect:/applications";
    }

    /**
     * Deletes the application Version with the specified id.
     * @param id The ID of the ApplicationVersion to delete
     * @return a String
     */
    @RequestMapping(value = "/deleteApplicationVersion/{id}", method = RequestMethod.GET)
    public String deleteApplicationVersion(@PathVariable("id") int id) {

        applicationVersionService.deleteApplicationVersion(id);

        return "redirect:/applications";
    }

    /**
     * Adds a version to an application.
     * @param id The ID of the Application
     * @param version The version label
     * @return a String
     */
    @RequestMapping(value = "/addApplicationVersion", method = RequestMethod.POST)
    public String addApplicationVersion(@RequestParam("id") int id, @RequestParam("version") String version) {
        applicationVersionService.addApplicationVersion(id, version);
        return "redirect:/applications";
    }

    /**
     * Returns a json list of the complete Library Hierarchy.
     * @param map a map of parameters
     * @return a String
     */
    @RequestMapping(value = "/libraryHierarchy", method = RequestMethod.GET)
    public String getLibraryHierarchy(Map<String, Object> map) {
        map.put("libraryVendors", libraryVersionService.getLibraryHierarchy());
        return "libraryHierarchy";
    }

    /**
     * Lists the data in the specified application version.
     * @param modelMap a Spring ModelMap
     * @param map a map of parameters
     * @param id the ID of the Application to list versions for
     * @return a String
     */
    @RequestMapping(value = "/applicationVersion/{id}", method = RequestMethod.GET)
    public String listApplicationVersion(ModelMap modelMap, Map<String, Object> map, @PathVariable("id") int id) {
        final ApplicationVersion version = applicationVersionService.getApplicationVersion(id);
        modelMap.addAttribute("id", id);
        map.put("applicationVersion", version);
        map.put("dependencies", libraryVersionService.getDependencies(version));
        map.put("libraryVendors", libraryVersionService.getLibraryHierarchy());
        return "applicationVersionPage";
    }

    /**
     * Adds a ApplicationDependency between the specified ApplicationVersion and LibraryVersion.
     * @param appversionid The ID of the ApplicationVersion
     * @param versionid The ID of the LibraryVersion
     * @return a String
     */
    @RequestMapping(value = "/addDependency", method = RequestMethod.POST)
    public String addDependency(@RequestParam("appversionid") int appversionid,
                                @RequestParam("versionid") int versionid) {
        libraryVersionService.addDependency(appversionid, versionid);
        return "redirect:/applicationVersion/" + appversionid;
    }

    /**
     * Deletes the dependency with the specified ApplicationVersion ID and LibraryVersion ID.
     * @param appversionid The ID of the ApplicationVersion
     * @param versionid The ID of the LibraryVersion
     * @return a String
     */
    @RequestMapping(value = "/deleteDependency", method = RequestMethod.GET)
    public String deleteDependency(@RequestParam("appversionid") int appversionid,
                                   @RequestParam("versionid") int versionid) {
        libraryVersionService.deleteDependency(appversionid, versionid);
        return "redirect:/applicationVersion/" + appversionid;
    }

    /**
     * Clone the Application including all ApplicationVersions.
     * @param modelMap A Spring ModelMap
     * @param applicationid The ID of the Application to clone
     * @param applicationname The name of the cloned Application
     * @return a String
     */
    @RequestMapping(value = "/cloneApplication", method = RequestMethod.POST)
    public String cloneApplication(ModelMap modelMap, @RequestParam("applicationid") int applicationid,
                                   @RequestParam("cloneAppName") String applicationname) {
        applicationVersionService.cloneApplication(applicationid, applicationname);
        return "redirect:/applications";
    }

    /**
     * Clone the ApplicationVersion.
     * @param modelMap a Spring ModelMap
     * @param applicationid The ID of the Application to clone
     * @param newversion The version of the cloned ApplicationVersion
     * @param applicationversion The ApplicationVersion to clone
     * @return
     */
    @RequestMapping(value = "/cloneApplicationVersion", method = RequestMethod.POST)
    public String cloneApplicationVersion(ModelMap modelMap, @RequestParam("applicationid") int applicationid,
                                          @RequestParam("cloneVersionNumber") String newversion,
                                          @RequestParam("applicationversion") String applicationversion) {
        applicationVersionService.cloneApplicationVersion(applicationid, newversion, applicationversion);
        return "redirect:/applications";
    }

    /**
     * Updates a library regardless of application association.
     * @param modelMap a Spring ModelMap
     * @param vendorid The ID of the LibraryVendor
     * @param licenseid The ID of the License
     * @param libraryid The ID of the Library
     * @param libraryversionid The ID of the LibraryVersion
     * @param libraryname The name of the Library
     * @param file The license file
     * @param libraryversion The version label of the Library
     * @param vendor The String representation of the Vendor
     * @param license The license the Library is licensed under
     * @param language The programming language the Library was written in
     * @param secuniaID The Secunia ID of the LibraryVersion
     * @return a String
     */
    @RequestMapping(value = "/updatelibrary", method = RequestMethod.POST)
    public String updatingLibrary(ModelMap modelMap,
                                  @RequestParam("editvendorid") int vendorid,
                                  @RequestParam("editlicenseid") int licenseid,
                                  @RequestParam("editlibraryid") int libraryid,
                                  @RequestParam("editlibraryversionid") int libraryversionid,

                                  @RequestParam("libraryname") String libraryname,
                                  @RequestParam("Licensefile") MultipartFile file,
                                  @RequestParam("libraryversion") String libraryversion,
                                  @RequestParam("vendor") String vendor,
                                  @RequestParam("license") String license,
                                  @RequestParam("language") String language,
                                  @RequestParam("secuniaID") int secuniaID) {

        libraryVersionService.updateLibrary(vendorid, licenseid, libraryid,
                libraryversionid, libraryname, libraryversion, vendor, license, file,
                language, secuniaID);
        return "redirect:/libraries";
    }

    /**
     * Remove the libraryVersion with the specified ID.
     * @param modelMap a Spring ModelMap
     * @param libraryversionid The LibraryVersion ID
     * @return a String
     */
    @RequestMapping(value = "/removelibrary/{libraryversionid}", method = RequestMethod.GET)
    public String removeLibrary(ModelMap modelMap,
                                @PathVariable("libraryversionid") Integer libraryversionid) {

        libraryVersionService.removeLibrary(libraryversionid);

        return "redirect:/libraries";
    }

    /**
     * Returns a list of all libraries regardless of application association
     * @param map a map of parameters
     * @return a String
     */
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
     * @param modelMap a Spring ModelMap
     * @param libraryname The name of the Library
     * @param libraryversion The version of the Library
     * @param vendor The vendor of the Library
     * @param license The license the Library is licensed under
     * @param file The license file
     * @param language The programming language the Library was written in
     * @param secuniaID The Secunia ID of the LibraryVersion
     * @return
     */
    @RequestMapping(value = "/addlibraries", method = RequestMethod.POST)
    public String addLibraries(ModelMap modelMap,
                               @RequestParam("libnamesel") String libraryname,
                               @RequestParam("libversel") String libraryversion,
                               @RequestParam("vendorsel") String vendor,
                               @RequestParam("licensesel") String license,
                               @RequestParam("Licensefile") MultipartFile file,
                               @RequestParam("languagesel") String language,
                               @RequestParam("secuniaID") int secuniaID) {

        libraryVersionService.addLibraries(libraryname, libraryversion, vendor, license, file, language, secuniaID);
        return "redirect:/libraries";
    }

    /**
     * Download license action.
     * @param map map of parameters
     * @param response a Response object
     * @param licenseid the ID of the License to download
     */
    @RequestMapping(value = "/downloadlicense", method = RequestMethod.POST)
    public void downloadLicense(Map<String, Object> map,
                                HttpServletResponse response,
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
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            IOUtils.closeQuietly(in);
            IOUtils.closeQuietly(out);
        }

    }

    /**
     * View license action.
     * @param map map of parameters
     * @param response a Response object
     * @param licenseid the ID of the License to download
     */
    @RequestMapping(value = "/viewlicense/{licenseid}", method = RequestMethod.GET)
    public String viewLicense(Map<String, Object> map,
                              HttpServletResponse response,
                              @PathVariable("licenseid") Integer licenseid) {

        final List<License> licenses = libraryVersionService.listLicense(licenseid);
        final License newLicense = licenses.get(0);
        if (newLicense.getContenttype().equals("text/plain") || newLicense.getContenttype().equals("text/html")) {

            InputStream in = null;
            OutputStream out = null;
            try {
                response.setHeader("Content-Disposition", "inline;filename=\"" + newLicense.getFilename() + "\"");
                in = newLicense.getText().getBinaryStream();
                out = response.getOutputStream();
                response.setContentType(newLicense.getContenttype());
                IOUtils.copy(in, out);
                out.flush();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (SQLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
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
     * The about page.
     * @return a String
     */
    @RequestMapping(value = "/about", method = RequestMethod.GET)
    public String about() {
        return "aboutPage";
    }

}
