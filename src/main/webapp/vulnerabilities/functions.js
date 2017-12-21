/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

"use strict";

/**
 * Called by bootstrap table to format the data in the vulnerability table.
 */
function formatVulnerabilityTable(res) {
    for (let i=0; i<res.length; i++) {
        let vulnurl = "../vulnerability/?source=" + res[i].source + "&vulnId=" + res[i].vulnId;
        res[i].vulnerabilityhref = $common.formatSourceLabel(res[i].source) + " <a href=\"" + vulnurl + "\">" + filterXSS(res[i].vulnId) + "</a>";

        if (res[i].hasOwnProperty("cwe")) {
            res[i].cwefield = "CWE-" + res[i].cwe.cweId + " " + res[i].cwe.name;
        }

        if (res[i].hasOwnProperty("severity")) {
            res[i].severityLabel = $common.formatSeverityLabel(res[i].severity);
        }

        if (res[i].hasOwnProperty("published")) {
            res[i].publishedLabel = $common.formatTimestamp(res[i].published);
        }
    }
    return res;
}

function updateStats(metric) {
    $("#statTotalProjects").html(filterXSS(metric.projects));
    $("#statVulnerableProjects").html(filterXSS(metric.vulnerableProjects));
    $("#statTotalComponents").html(filterXSS(metric.components));
    $("#statVulnerableComponents").html(filterXSS(metric.vulnerableComponents));
    $("#statPortfolioVulnerabilities").html(filterXSS(metric.vulnerabilities));
    $("#statLastMeasurement").html(filterXSS($common.formatTimestamp(metric.lastOccurrence, true)));
    $("#statInheritedRiskScore").html(filterXSS(metric.inheritedRiskScore));
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready.
 */
$(document).ready(function () {

    $rest.getPortfolioCurrentMetrics(function(metrics) {
        updateStats(metrics);
    });

});