/*
 * Copyright 2013 Axway
 *
 * This file is part of OWASP Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with Dependency-Track.
 * If not, see http://www.gnu.org/licenses/.
 */

package org.owasp.dependencytrack.controller;

import org.apache.commons.io.IOUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.owasp.dependencytrack.model.*;
import org.owasp.dependencytrack.service.ApplicationService;
import org.owasp.dependencytrack.service.ApplicationVersionService;
import org.owasp.dependencytrack.service.LibraryVersionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

@Controller
public class ApplicationController {

    private static final Logger logger = LoggerFactory.getLogger(ApplicationController.class);

    @Autowired
    private ApplicationService applicationService;

    @Autowired
    private ApplicationVersionService applicationVersionService;

    @Autowired
    private LibraryVersionService libraryVersionService;

    @PostConstruct
    public void init() {
        logger.info("OWASP Dependency-Track Initialized");
    }

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String loginchk(@RequestParam("username") String username,
                           @RequestParam("password") String passwd, ModelMap modelMap) {
        UsernamePasswordToken token = new UsernamePasswordToken(username,
                passwd);
        try {
            SecurityUtils.getSubject().login(token);
        } catch (AuthenticationException e) {

        }
        return "redirect:/login";

    }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(ModelMap modelMap) {
        String s = "login";
        if (SecurityUtils.getSubject().isAuthenticated()) {
            s = "redirect:/home";
        }
        return s;
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout(ModelMap modelMap) {
        SecurityUtils.getSubject().logout();
        return "redirect:/login";
    }

    /*
     * Default page
     */
    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String application() {
        return "redirect:/applications";
    }

    /*
     * Lists all applications
     */
    @RequestMapping(value = "/applications", method = RequestMethod.GET)
    public String application(Map<String, Object> map) {
        map.put("check",false);
        map.put("application", new Application());
        map.put("applicationList", applicationService.listApplications());
        return "applicationsPage";
    }

    /*SEARCH APPLICATION*/
    @RequestMapping(value = "/searchApplication", method = RequestMethod.POST)
    public String searchApplication(Map<String, Object> map, @RequestParam("serapplib") int libid, @RequestParam("serapplibver") int libverid) {

        map.put("applicationList", applicationService.searchApplications(libverid));

         map.put("versionlist",applicationService.searchApplicationsVersion(libverid));
        List <ApplicationVersion> av = applicationService.searchApplicationsVersion(libverid);
                       System.out.println("version check "+ av.get(0).getVersion());
        System.out.println("version check "+ av.get(0).getApplication().getName());
        map.put("check",true);
        return "applicationsPage";
    }

    /*
     * Adds an application and associated version number
     */
    @RequestMapping(value = "/addApplication", method = RequestMethod.POST)
    public String addApplication(@ModelAttribute("application") Application application,
                                 BindingResult result, @RequestParam("version") String version) {
        applicationService.addApplication(application, version);
        return "redirect:/applications";
    }

    /*
     * Updates an applications' name
     */
    @RequestMapping(value = "/updateApplication", method = RequestMethod.POST)
    public String updatingProduct(@RequestParam("id") int id, @RequestParam("name") String name) {
        applicationService.updateApplication(id, name);
        return "redirect:/applications";
    }

    /*
     * Updates an applications' version
     */
    @RequestMapping(value = "/updateApplicationVersion", method = RequestMethod.POST)
    public String updatingApplicationVersion(@RequestParam("appversionid") int id, @RequestParam("editappver") String appversion) {
        applicationVersionService.updateApplicationVersion(id, appversion);

        return "redirect:/applications";
    }

    /*
     * Deletes the application with the specified id
     */
    @RequestMapping(value = "/deleteApplication/{id}", method = RequestMethod.GET)
    public String removeApplication(@PathVariable("id") int id) {
        applicationService.deleteApplication(id);
        return "redirect:/applications";
    }

    /*
    * Deletes the application Version with the specified id
    */
    @RequestMapping(value = "/deleteApplicationVersion/{id}", method = RequestMethod.GET)
    public String deleteApplicationVersion(@PathVariable("id") int id) {

        applicationVersionService.deleteApplicationVersion(id);

        return "redirect:/applications";
    }

    /*
     * Adds a version to an application
     */
    @RequestMapping(value = "/addApplicationVersion", method = RequestMethod.POST)
    public String addApplicationVersion(@RequestParam("id") int id, @RequestParam("version") String version) {
        applicationVersionService.addApplicationVersion(id, version);
        return "redirect:/applications";
    }

    /*
     * Returns a json list of the complete Library Hierarchy
     */
    @RequestMapping(value = "/libraryHierarchy", method = RequestMethod.GET)
    public String getLibraryHierarchy(Map<String, Object> map) {
        map.put("libraryVendors", libraryVersionService.getLibraryHierarchy());
        return "libraryHierarchy";
    }

    /*
     * Lists the data in the specified application version
     */
    @RequestMapping(value = "/applicationVersion/{id}", method = RequestMethod.GET)
    public String listApplicationVersion(ModelMap modelMap, Map<String, Object> map, @PathVariable("id") int id) {
        ApplicationVersion version = applicationVersionService.getApplicationVersion(id);
        modelMap.addAttribute("id", id);
        map.put("applicationVersion", version);
        map.put("dependencies", libraryVersionService.getDependencies(version));
        map.put("libraryVendors", libraryVersionService.getLibraryHierarchy());
        return "applicationVersionPage";
    }

    /*
     * Adds a ApplicationDependency between the specified ApplicationVersion and LibraryVersion
     */
    @RequestMapping(value = "/addDependency", method = RequestMethod.POST)
    public String addDependency(@RequestParam("appversionid") int appversionid,
                                @RequestParam("versionid") int versionid) {
        libraryVersionService.addDependency(appversionid, versionid);
        return "redirect:/applicationVersion/" + appversionid;
    }

    /*
     * Deletes the dependency with the specified ApplicationVersion ID and LibraryVersion ID
     */
    @RequestMapping(value = "/deleteDependency", method = RequestMethod.GET)
    public String deleteDependency(@RequestParam("appversionid") int appversionid,
                                   @RequestParam("versionid") int versionid) {
        libraryVersionService.deleteDependency(appversionid, versionid);
        return "redirect:/applicationVersion/" + appversionid;
    }


    /*CLONE APPLICATION INCLUDING ALL VERSION*/

    @RequestMapping(value = "/cloneApplication", method = RequestMethod.POST)
    public String cloneApplication(ModelMap modelMap, @RequestParam("applicationid") int applicationid, @RequestParam("cloneAppName") String applicationname)
    {

        applicationVersionService.cloneApplication(applicationid, applicationname);


        return "redirect:/applications";
    }


     /*CLONE APPLICATION VERSION INCLUDING ALL VERSION*/

    @RequestMapping(value = "/cloneApplicationVersion", method = RequestMethod.POST)
    public String cloneApplicationVersion(ModelMap modelMap, @RequestParam("applicationid") int applicationid, @RequestParam("cloneVersionNumber") String newversion, @RequestParam("applicationversion") String applicationversion)
    {

        applicationVersionService.cloneApplicationVersion(applicationid, newversion, applicationversion);


        return "redirect:/applications";
    }


	/*
	 * ------ Applications and Version end ------
	 */

	/*
	 * ------ Library start ------
	 */


     /*
      Updates a library regardless of application association
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
                                  @RequestParam("secuniaID") int secuniaID ) {

        libraryVersionService.updateLibrary(vendorid, licenseid, libraryid,
                libraryversionid, libraryname, libraryversion, vendor, license, file,
                language, secuniaID);



        return "redirect:/libraries";
    }

    @RequestMapping(value = "/removelibrary/{libraryversionid}", method = RequestMethod.GET)
    public String removeLibrary(ModelMap modelMap,
                                @PathVariable("libraryversionid") Integer libraryversionid) {

        libraryVersionService.removeLibrary(libraryversionid);

        return "redirect:/libraries";
    }


    /*
       Returns a list of all libraries regardless of application association
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

    /*
      Adds a library regardless of application association
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

        libraryVersionService.addLibraries(libraryname,libraryversion, vendor, license, file, language, secuniaID);

        return "redirect:/libraries" ;
    }
	

	/*
	 * ------ Library end ------
	 */

	/*
	 * ------ License start ------
	 */

    @RequestMapping(value = "/downloadlicense", method = RequestMethod.POST)
    public void downloadLicense(Map<String, Object> map,
                                HttpServletResponse response,
                                @RequestParam("licenseid") Integer licenseid) {




        List<License> licenses = libraryVersionService.listLicense(licenseid);
        License newLicense = licenses.get(0);


        try {

            response.setHeader("Content-Disposition", "inline;filename=\""
                    + newLicense.getFilename() + "\"");
            response.setHeader("Content-Type", "application/octet-stream;");
            OutputStream out = response.getOutputStream();
            IOUtils.copy(newLicense.getText().getBinaryStream(), out);
            out.flush();
            out.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        }


    @RequestMapping(value = "/viewlicense/{licenseid}", method = RequestMethod.GET)
    public String viewLicense(Map<String, Object> map,
                            HttpServletResponse response,
                            @PathVariable("licenseid") Integer licenseid) {


        List<License> licenses = libraryVersionService.listLicense(licenseid);
        License newLicense = licenses.get(0);
        if (newLicense.getContenttype().equals("text/plain")||newLicense.getContenttype().equals("text/html"))
        {
        try {

            response.setHeader("Content-Disposition", "inline;filename=\""
                    + newLicense.getFilename() + "\"");
            OutputStream out = response.getOutputStream();

            response.setContentType(newLicense.getContenttype());
            IOUtils.copy(newLicense.getText().getBinaryStream(), out);

            out.flush();
            out.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        }
        else
        {
            System.out.println("in else");
        return "emptyfile";
    }
        return "";
    }


    /*

        The about page
     */
    @RequestMapping(value = "/about", method = RequestMethod.GET)
    public String about() {
        return "aboutPage";
    }


	/*
	 * ------ License start ------
	 */

}