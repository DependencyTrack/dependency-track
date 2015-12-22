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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Function;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.VulnerabilitySummary;
import org.owasp.dependencytrack.service.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Nullable;
import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.google.common.collect.Collections2.transform;

/**
 * Controller logic for all Application-related requests.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Controller
public class ApplicationController extends AbstractController {

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
     * The Dependency-Track VulnerabilityService.
     */
    @Autowired
    private VulnerabilityService vulnerabilityService;

    /**
     * The Dependency-Track LibraryVersionService.
     */
    @Autowired
    private LibraryVersionService libraryVersionService;

    /**
     * The Dependency-Track ReportService.
     */
    @Autowired
    private ReportService reportService;

    /**
     * Initialization method gets called after controller is constructed.
     */
    @PostConstruct
    public void init() {
        LOGGER.info("OWASP Dependency-Track Initialized");
    }

    /**
     * Lists all applications.
     *
     * @param map     A map of parameters
     * @return a String
     */
    @RequiresPermissions("applications")
    @RequestMapping(value = "/applications", method = RequestMethod.GET)
    public String application(Map<String, Object> map) {
        map.put("check", false);
        map.put("applicationList", applicationService.listApplications());
        return "applicationsPage";
    }

    /**
     * Lists vulnerability summary information for the specified application.
     *
     * @param map A map of parameters
     * @param id  The ID of the Application to retrieve vulnerability info for
     * @return a String
     */
    @RequiresPermissions("applications")
    @RequestMapping(value = "/vulnerabilitySummary/{id}", method = RequestMethod.GET)
    @ResponseBody
    public List<VulnerabilitySummaryDTO> vulnerabiltySummary(Map<String, Object> map, @PathVariable("id") int id) {

        ArrayList arrayList = new ArrayList();
        arrayList.addAll(transform(vulnerabilityService.getVulnerabilitySummary(id), new Function<VulnerabilitySummary, VulnerabilitySummaryDTO>() {
            @Nullable
            @Override
            public VulnerabilitySummaryDTO apply(VulnerabilitySummary input) {
                return new VulnerabilitySummaryDTO(input);
            }
        }));
        return arrayList;
    }

    public static class VulnerabilitySummaryDTO {
        @JsonProperty("application-version-id")
        public long applicationVersionId;
        public int vulnerableComponents;
        public int high;
        public int medium;
        public int low;

        public VulnerabilitySummaryDTO() {
        }

        public VulnerabilitySummaryDTO(VulnerabilitySummary input) {
            applicationVersionId = input.getApplicationVersion().getId();
            vulnerableComponents = input.getVulnerableComponents();
            high = input.getHigh();
            medium = input.getMedium();
            low = input.getLow();
        }
    }

    /**
     * Dynamically generates a native Dependency-Check XML report.
     *
     * @param map A map of parameters
     * @param id  The ID of the Application to create a report for
     * @return A String representation of the XML report
     */
    @RequestMapping(value = "/dependencyCheckReport/{id}.xml", method = RequestMethod.GET, produces = "application/xml")
    @ResponseBody
    public String dependencyCheckXmlReport(Map<String, Object> map, @PathVariable("id") int id) {
        return reportService.generateDependencyCheckReport(id, ReportGenerator.Format.XML);
    }

    /**
     * Dynamically generates a native Dependency-Check HTML report.
     *
     * @param map A map of parameters
     * @param id  The ID of the Application to create a report for
     * @return A String representation of the HTML report
     */
    @RequestMapping(value = "/dependencyCheckReport/{id}.html", method = RequestMethod.GET, produces = "text/html")
    @ResponseBody
    public String dependencyCheckHtmlReport(Map<String, Object> map, @PathVariable("id") int id) {
        return reportService.generateDependencyCheckReport(id, ReportGenerator.Format.HTML);
    }

    /**
     * Search action.
     *
     * @param map      a map of parameters
     * @param libid    the ID of the Library to search on
     * @param libverid The ID of the LibraryVersion to search on
     * @return a String
     */
    @RequiresPermissions("searchApplication")
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
     *
     * @param map      a map of parameters
     * @param vendorId The ID of the Vendor to search on
     * @return a String
     */
    @RequiresPermissions("coarseSearchApplication")
    @RequestMapping(value = "/coarseSearchApplication", method = RequestMethod.POST)
    public String coarseSearchApplication(Map<String, Object> map, @RequestParam("coarseSearchVendor") int vendorId) {

        map.put("applicationList", applicationService.coarseSearchApplications(vendorId));
        map.put("versionlist", applicationService.coarseSearchApplicationVersions(vendorId));
        map.put("check", true);
        return "applicationsPage";
    }

    /**
     * Search action.
     *
     * @param map        a map of parameters
     * @param searchTerm is the search term
     * @return a String
     */
    @RequiresPermissions("keywordSearchLibraries")
    @RequestMapping(value = "/keywordSearchLibraries", method = RequestMethod.POST)
    public String keywordSearchLibraries(Map<String, Object> map,
                                         @RequestParam("keywordSearchVendor") String searchTerm) {
        map.put("libList", libraryVersionService.keywordSearchLibraries(searchTerm));
        return "librariesPage";
    }

    /**
     * Add Application action. Adds an application and associated version number
     *
     * @param application The Application to add
     * @param version     a String of the version number to add
     * @return a String
     */
    @RequiresPermissions("addApplication")
    @RequestMapping(value = "/addApplication", method = RequestMethod.POST)
    public String addApplication(@ModelAttribute("application") Application application,
                                 @RequestParam("version") String version) {
        applicationService.addApplication(application, version);
        return "redirect:/applications";
    }

    /**
     * Updates an applications' name.
     *
     * @param id   The ID of the application to update
     * @param name The updated name of the application
     * @return a String
     */
    @RequiresPermissions("updateApplication")
    @RequestMapping(value = "/updateApplication", method = RequestMethod.POST)
    public String updatingProduct(@RequestParam("id") int id, @RequestParam("name") String name) {
        applicationService.updateApplication(id, name);
        return "redirect:/applications";
    }

    /**
     * Updates an applications' version.
     *
     * @param id         The ID of the ApplicationVersion
     * @param appversion The version label
     * @return a String
     */
    @RequiresPermissions("updateApplicationVersion")
    @RequestMapping(value = "/updateApplicationVersion", method = RequestMethod.POST)
    public String updatingApplicationVersion(@RequestParam("appversionid") int id,
                                             @RequestParam("editappver") String appversion) {
        applicationVersionService.updateApplicationVersion(id, appversion);
        return "redirect:/applications";
    }

    /**
     * Deletes the application with the specified id.
     *
     * @param id The ID of the Application to delete
     * @return a String
     */
    @RequiresPermissions("deleteApplication")
    @RequestMapping(value = "/deleteApplication/{id}", method = RequestMethod.GET)
    public String removeApplication(@PathVariable("id") int id) {
        applicationService.deleteApplication(id);
        return "redirect:/applications";
    }

    /**
     * Deletes the application Version with the specified id.
     *
     * @param id The ID of the ApplicationVersion to delete
     * @return a String
     */
    @RequiresPermissions("deleteApplicationVersion")
    @RequestMapping(value = "/deleteApplicationVersion/{id}", method = RequestMethod.GET)
    public String deleteApplicationVersion(@PathVariable("id") int id) {

        applicationVersionService.deleteApplicationVersion(id);
        return "redirect:/applications";
    }

    /**
     * Adds a version to an application.
     *
     * @param id      The ID of the Application
     * @param version The version label
     * @return a String
     */
    @RequiresPermissions("addApplicationVersion")
    @RequestMapping(value = "/addApplicationVersion", method = RequestMethod.POST)
    public String addApplicationVersion(@RequestParam("id") int id, @RequestParam("version") String version) {
        applicationVersionService.addApplicationVersion(id, version);
        return "redirect:/applications";
    }

    /**
     * Lists the data in the specified application version.
     *
     * @param modelMap a Spring ModelMap
     * @param map      a map of parameters
     * @param id       the ID of the Application to list versions for
     * @return a String
     */
    @RequiresPermissions("applicationVersion")
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
     *
     * @param appversionid The ID of the ApplicationVersion
     * @param versionid    The ID of the LibraryVersion
     * @return a String
     */
    @RequiresPermissions("addDependency")
    @RequestMapping(value = "/addDependency", method = RequestMethod.POST)
    public String addDependency(@RequestParam("appversionid") int appversionid,
                                @RequestParam("versionid") int versionid) {
        libraryVersionService.addDependency(appversionid, versionid);
        return "redirect:/applicationVersion/" + appversionid;
    }

    /**
     * Deletes the dependency with the specified ApplicationVersion ID and LibraryVersion ID.
     *
     * @param appversionid The ID of the ApplicationVersion
     * @param versionid    The ID of the LibraryVersion
     * @return a String
     */
    @RequiresPermissions("deleteDependency")
    @RequestMapping(value = "/deleteDependency", method = RequestMethod.GET)
    public String deleteDependency(@RequestParam("appversionid") int appversionid,
                                   @RequestParam("versionid") int versionid) {
        libraryVersionService.deleteDependency(appversionid, versionid);
        return "redirect:/applicationVersion/" + appversionid;
    }

    /**
     * Clone the Application including all ApplicationVersions.
     *
     * @param applicationid   The ID of the Application to clone
     * @param applicationname The name of the cloned Application
     * @return a String
     */
    @RequiresPermissions("cloneApplication")
    @RequestMapping(value = "/cloneApplication", method = RequestMethod.POST)
    public String cloneApplication(@RequestParam("applicationid") int applicationid,
                                   @RequestParam("cloneAppName") String applicationname) {
        applicationVersionService.cloneApplication(applicationid, applicationname);
        return "redirect:/applications";
    }

    /**
     * Clone the ApplicationVersion.
     *
     * @param applicationid      The ID of the Application to clone
     * @param newversion         The version of the cloned ApplicationVersion
     * @param applicationversion The ApplicationVersion to clone
     * @return a String
     */
    @RequiresPermissions("cloneApplicationVersion")
    @RequestMapping(value = "/cloneApplicationVersion", method = RequestMethod.POST)
    public String cloneApplicationVersion(@RequestParam("applicationid") int applicationid,
                                          @RequestParam("cloneVersionNumber") String newversion,
                                          @RequestParam("applicationversion") String applicationversion) {
        applicationVersionService.cloneApplicationVersion(applicationid, newversion, applicationversion);
        return "redirect:/applications";
    }

    /**
     * Lists the vulnerability data in the specified application version.
     *
     * @param modelMap a Spring ModelMap
     * @param map      a map of parameters
     * @param id       the ID of the Application to list versions for
     * @return a String
     */
    @RequiresPermissions("vulnerabilities")
    @RequestMapping(value = "/vulnerabilities/{id}", method = RequestMethod.GET)
    public String listVulnerabilityData(ModelMap modelMap, Map<String, Object> map, @PathVariable("id") int id) {
        final ApplicationVersion version = applicationVersionService.getApplicationVersion(id);
        modelMap.addAttribute("id", id);
        map.put("applicationVersion", version);
        map.put("dependencies", libraryVersionService.getDependencies(version));
        map.put("libraryVendors", libraryVersionService.getLibraryHierarchy());
        map.put("vulnerableComponents", vulnerabilityService.getVulnerableComponents(version));
        return "vulnerabilitiesPage";
    }

    /**
     * The about page.
     *
     * @return a String
     */
    @RequiresPermissions("about")
    @RequestMapping(value = "/about", method = RequestMethod.GET)
    public String about() {
        return "aboutPage";
    }

    /**
     * Performs an immediate scan against all library versions.
     *
     * @return a String
     */
    @RequiresRoles("admin")
    @RequestMapping(value = "/about/scan", method = RequestMethod.GET)
    public String scanNow() {
        vulnerabilityService.initiateFullDependencyCheckScan();
        return "redirect:/about";
    }

    /**
     * Upload a License.
     *
     * @param licenseid       the ID of the License to download
     * @param file            the license file to upload
     * @param editlicensename an updated license name
     * @return a String
     */
    @RequiresPermissions("uploadlicense")
    @RequestMapping(value = "/uploadlicense", method = RequestMethod.POST)
    public String uploadLicense(@RequestParam("uploadlicenseid") Integer licenseid,
                                @RequestParam("uploadlicensefile") MultipartFile file,
                                @RequestParam("editlicensename") String editlicensename) {
        libraryVersionService.uploadLicense(licenseid, file, editlicensename);
        return "redirect:/libraries";
    }

    /**
     * Limits what fields can be automatically bound.
     *
     * @param binder a WebDataBinder object
     */
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        if (binder.getTarget() instanceof Application) {
            binder.setAllowedFields("name");
        }
    }
}
