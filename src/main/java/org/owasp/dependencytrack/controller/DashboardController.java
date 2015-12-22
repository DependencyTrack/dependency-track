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

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.owasp.dependencytrack.model.VulnerabilitySummary;
import org.owasp.dependencytrack.model.VulnerabilityTrend;
import org.owasp.dependencytrack.service.VulnerabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;
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
     * @param days the number of days back to get statistics for
     * @return a String
     */
    @RequiresPermissions("vulnerabilities")
    @RequestMapping(value = "/vulnerabilityTrend/{days}", method = RequestMethod.GET, produces = "application/json")
    @ResponseBody
    @SuppressWarnings("unchecked")
    public String vulnerabilityTrend(@PathVariable("days") Integer days) {
        final VulnerabilityTrend.Timespan timespan = VulnerabilityTrend.Timespan.getTimespan(days);
        final VulnerabilityTrend trend = vulnerabilityService.getVulnerabilityTrend(timespan, -1);
        final JSONArray jsonArray = new JSONArray();
        for (Map.Entry<Date, VulnerabilitySummary> entry : trend.getTrend().entrySet()) {
            final VulnerabilitySummary vs = entry.getValue();
            final JSONObject jsonObject = new JSONObject();
            jsonObject.put("date", entry.getKey().toString());
            jsonObject.put("high", vs.getHigh());
            jsonObject.put("medium", vs.getMedium());
            jsonObject.put("low", vs.getLow());
            jsonObject.put("total", vs.getHigh() + vs.getMedium() + vs.getLow());
            jsonArray.add(jsonObject);
        }
        return jsonArray.toJSONString();
    }

    /**
     * Mapping to dashboard which gives vulnerability overview.
     * @param map a map of parameters
     * @return a String
     */
    @RequiresPermissions("dashboard")
    @RequestMapping(value = "/dashboard", method = RequestMethod.GET)
    public String dashboard(Map<String, Object> map) {
        return "dashboardPage";
    }

}
