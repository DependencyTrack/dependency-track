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

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.VulnerabilityTrend;
import org.owasp.dependencytrack.service.ApplicationService;
import org.owasp.dependencytrack.service.ApplicationVersionService;
import org.owasp.dependencytrack.service.VulnerabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller logic for all Dashboard-related requests.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Controller
public class DashboardController extends AbstractController {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DashboardController.class);

    /**
     * The Dependency-Track VulnerabilityService.
     */
    @Autowired
    private VulnerabilityService vulnerabilityService;

    /**
     * Returns a json reponse of vulnerability trends.
     *
     * @param map a map of parameters
     * @return a String
     */
    //  @RequiresPermissions("libraryHierarchy")
    @RequestMapping(value = "/vulnerabilityTrend", method = RequestMethod.GET)
    public String getLibraryHierarchy(Map<String, Object> map) {
        final VulnerabilityTrend trend = vulnerabilityService.getVulnerabilityTrend(VulnerabilityTrend.Timespan.MONTH, -1);
        return "dashboardPage";
    }

    /**
     * Mapping to dashboard which gives vulnerability overview.
     */
    @RequiresPermissions("dashboard")
    @RequestMapping(value = "/dashboard", method = RequestMethod.GET)
    public String dashboard(Map<String, Object> map) {
        return "dashboardPage";
    }

}
