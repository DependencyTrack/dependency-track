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
import org.owasp.dependencytrack.Config;
import org.owasp.dependencytrack.Constants;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.service.ApplicationService;
import org.owasp.dependencytrack.service.ApplicationVersionService;
import org.owasp.dependencytrack.service.LibraryVersionService;
import org.owasp.dependencytrack.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
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
     * The Dependency-Track UserService.
     */
    @Autowired
    private UserService userService;

    /**
     * The Dependency-Track LibraryVersionService.
     */
    @Autowired
    private LibraryVersionService libraryVersionService;

    /**
     * Dependency-Track's centralized Configuration class
     */
    @Autowired
    private Config config;

    /**
     * Initialization method gets called after controller is constructed.
     */
    @PostConstruct
    public void init() {
        LOGGER.info("OWASP Dependency-Track Initialized");
    }

    /**
     * Login action.
     * @param map Map
     * @param username The username to login with
     * @param passwd The password to login with
     * @return A String
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String loginchk(Map<String, Object> map,
                           @RequestParam("username") String username, @RequestParam("password") String passwd) {
        final String pwd = userService.hashpwd(username, passwd);
        final UsernamePasswordToken token = new UsernamePasswordToken(username, pwd);
        try {
            SecurityUtils.getSubject().login(token);

            LOGGER.info("Login successful: " + username);
            if (SecurityUtils.getSubject().isAuthenticated()) {
                return "redirect:/applications";
            }
        } catch (AuthenticationException e) {
            LOGGER.info("Login failure: " + username);
            map.put("authenticationException", true);
        }
        return "loginPage";
    }

    /**
     * Login action.
     * @return a String
     */
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login() {
        final String s = "loginPage";
        if (SecurityUtils.getSubject().isAuthenticated()) {
            return "redirect:/applications";
        }
        return s;
    }

    /**
     * Logout action.
     * @return a String
     */
    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout() {
        SecurityUtils.getSubject().logout();
        return "redirect:/login";
    }

    /**
     * Logout action.
     * @param username The username supplied during the registration of a user account
     * @param password The password supplied during the registration of a user account
     * @param chkpassword The second password (retype) supplied during the registration of a user account
     * @return a String
     */
    @RequestMapping(value = "/registerUser", method = RequestMethod.POST)
    public String registerUser(@RequestParam("username") String username,
                               @RequestParam("password") String password,
                               @RequestParam("chkpassword") String chkpassword) {
        if (config.isSignupEnabled() && password.equals(chkpassword)) {
            userService.registerUser(username, password);
        }
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
     * Search action.
     * @param map a map of parameters
     * @param vendorId The ID of the Vendor to search on
     * @return a String
     */
    @RequestMapping(value = "/coarseSearchApplication", method = RequestMethod.POST)
    public String coarseSearchApplication(Map<String, Object> map, @RequestParam("coarseSearchVendor") int vendorId)
    {

        map.put("applicationList", applicationService.coarseSearchApplications(vendorId));
        map.put("versionlist", applicationService.coarseSearchApplicationVersions(vendorId));
        map.put("check", true);
        return "applicationsPage";
    }

    /**
     * Search action.
     * @param map a map of parameters
     * @param searchTerm is the search term
     * @return a String
     */
    @RequestMapping(value = "/keywordSearchLibraries", method = RequestMethod.POST)
    public String keywordSearchLibraries(Map<String, Object> map, @RequestParam("keywordSearchVendor") String searchTerm)
    {
        map.put("libList", libraryVersionService.keywordSearchLibraries(searchTerm));

        return "librariesPage";
    }

    /**
     * Add Application action. Adds an application and associated version number
     * @param application The Application to add
     * @param version a String of the version number to add
     * @return a String
     */
    @RequestMapping(value = "/addApplication", method = RequestMethod.POST)
    public String addApplication(@ModelAttribute("application") Application application,
                                 @RequestParam("version") String version) {
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
     * @param applicationid The ID of the Application to clone
     * @param applicationname The name of the cloned Application
     * @return a String
     */
    @RequestMapping(value = "/cloneApplication", method = RequestMethod.POST)
    public String cloneApplication(@RequestParam("applicationid") int applicationid,
                                   @RequestParam("cloneAppName") String applicationname) {
        applicationVersionService.cloneApplication(applicationid, applicationname);
        return "redirect:/applications";
    }

    /**
     * Clone the ApplicationVersion.
     * @param applicationid The ID of the Application to clone
     * @param newversion The version of the cloned ApplicationVersion
     * @param applicationversion The ApplicationVersion to clone
     * @return a String
     */
    @RequestMapping(value = "/cloneApplicationVersion", method = RequestMethod.POST)
    public String cloneApplicationVersion(@RequestParam("applicationid") int applicationid,
                                          @RequestParam("cloneVersionNumber") String newversion,
                                          @RequestParam("applicationversion") String applicationversion) {
        applicationVersionService.cloneApplicationVersion(applicationid, newversion, applicationversion);
        return "redirect:/applications";
    }

    /**
     * Updates a library regardless of application association.
     * @param vendorid The ID of the LibraryVendor
     * @param licenseid The ID of the License
     * @param libraryid The ID of the Library
     * @param libraryversionid The ID of the LibraryVersion
     * @param libraryname The name of the Library
     * @param libraryversion The version label of the Library
     * @param vendor The String representation of the Vendor
     * @param license The license the Library is licensed under
     * @param language The programming language the Library was written in
     * @param secuniaID The Secunia ID of the LibraryVersion
     * @return a String
     */
    @RequestMapping(value = "/updatelibrary", method = RequestMethod.POST)
    public String updatingLibrary(@RequestParam("editvendorid") int vendorid,
                                  @RequestParam("editlicenseid") int licenseid,
                                  @RequestParam("editlibraryid") int libraryid,
                                  @RequestParam("editlibraryversionid") int libraryversionid,
                                  @RequestParam("libraryname") String libraryname,
                                  @RequestParam("libraryversion") String libraryversion,
                                  @RequestParam("vendor") String vendor,
                                  @RequestParam("license") String license,
                                  @RequestParam("language") String language,
                                  @RequestParam(value="secuniaID", required=false) Integer secuniaID) {

        libraryVersionService.updateLibrary(vendorid, licenseid, libraryid,
                libraryversionid, libraryname, libraryversion, vendor, license,
                language, secuniaID);
        return "redirect:/libraries";
    }

    /**
     * Remove the libraryVersion with the specified ID.
     * @param libraryversionid The LibraryVersion ID
     * @return a String
     */
    @RequestMapping(value = "/removelibrary/{libraryversionid}", method = RequestMethod.GET)
    public String removeLibrary(@PathVariable("libraryversionid") Integer libraryversionid) {
        libraryVersionService.removeLibrary(libraryversionid);
        return "redirect:/libraries";
    }

    /**
     * Returns a list of all libraries regardless of application association.
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
     * @param libraryname The name of the Library
     * @param libraryversion The version of the Library
     * @param vendor The vendor of the Library
     * @param license The license the Library is licensed under
     * @param file The license file
     * @param language The programming language the Library was written in
     * @param secuniaID The Secunia ID of the LibraryVersion
     * @return a String
     */
    @RequestMapping(value = "/addlibraries", method = RequestMethod.POST)
    public String addLibraries(@RequestParam("libnamesel") String libraryname,
                               @RequestParam("libversel") String libraryversion,
                               @RequestParam("vendorsel") String vendor,
                               @RequestParam("licensesel") String license,
                               @RequestParam("Licensefile") MultipartFile file,
                               @RequestParam("languagesel") String language,
                               @RequestParam(value="secuniaID", required=false) Integer secuniaID) {

        libraryVersionService.addLibraries(libraryname, libraryversion, vendor, license, file, language, secuniaID);
        return "redirect:/libraries";
    }

    /**
     * Download license action.
     * @param response a Response object
     * @param licenseid the ID of the License to download
     */
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
     * @param response a Response object
     * @param licenseid the ID of the License to download
     * @return a String
     */
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
     * Service to download the Dependency-Check datafile archive.
     * @param response an HttpServletResponse object
     */
    @RequestMapping(value = "/dcdata", method = RequestMethod.GET)
    public void getFile(HttpServletResponse response) {
        InputStream fis = null;
        OutputStream out = null;
        try {
            fis = new FileInputStream(Constants.DATA_ZIP);
            response.setHeader("Content-Disposition", "inline;filename=\"" + Constants.DATA_FILENAME + "\"");
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
     * The about page.
     * @return a String
     */
    @RequestMapping(value = "/about", method = RequestMethod.GET)
    public String about() {
        return "aboutPage";
    }

    /**
     * Upload a License
     *@param licenseid the ID of the License to download
     */
    @RequestMapping(value = "/uploadlicense", method = RequestMethod.POST)
    public String uploadLicense(@RequestParam("uploadlicenseid") Integer licenseid,
                              @RequestParam("uploadlicensefile") MultipartFile file,
                              @RequestParam("editlicensename") String editlicensename)
    {
                libraryVersionService.uploadLicense(licenseid, file, editlicensename);
        return "redirect:/libraries";
    }

    /**
     * Admin User Management
     */
    @RequestMapping(value = "/usermanagement", method = RequestMethod.GET)
    public String userManagement(Map<String, Object> map)
    {
    map.put("userList",userService.accountManagement());
    return "userManagementPage";
    }


    /**
     * Admin User Management which validates a user
     */
    @RequestMapping(value = "/validateuser/{id}", method = RequestMethod.GET)
    public String validateUser(@PathVariable("id") Integer userid)
    {

        userService.validateuser(userid);

        return "userManagementPage";
    }

    /**
     * Admin User Management which deletes a user
     */
    @RequestMapping(value = "/deleteuser/{id}", method = RequestMethod.GET)
    public String deleteUser(@PathVariable("id") Integer userid)
    {

        userService.deleteUser(userid);

        return "userManagementPage";
    }

    /**
     * Mapping to dashboard which gives vulnerability overview
     */
    @RequestMapping(value = "/dashboard", method = RequestMethod.GET)
    public String dashboard(Map<String, Object> map)
    {
        map.put("application", new Application());
        map.put("applicationList", applicationService.listApplications());
        return "dashboardPage";
    }
}