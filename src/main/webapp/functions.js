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

function populateProgressBars(metrics) {
    if (!metrics || metrics.length === 0) {
        return;
    }
    let metric = metrics[metrics.length - 1]; //Use the most recent metric

    let vulnerableProjects = $("#vulnerableProjects");
    vulnerableProjects.html(filterXSS($common.valueWithDefault(metric.vulnerableProjects, "0")) + " / " + filterXSS($common.valueWithDefault(metric.projects, "0")));
    vulnerableProjects.css("width",((metric.vulnerableProjects / metric.projects) * 100 )+ "%");

    let vulnerableComponents = $("#vulnerableComponents");
    vulnerableComponents.html(filterXSS($common.valueWithDefault(metric.vulnerableComponents, "0")) + " / " + filterXSS($common.valueWithDefault(metric.components, "0")));
    vulnerableComponents.css("width",((metric.vulnerableComponents / metric.components) * 100 )+ "%");
}

function updateStats(metrics) {
    if (!metrics || metrics.length === 0) {
        return;
    }
    let metric = metrics[metrics.length - 1]; //Use the most recent metric
    $("#projectsAtRisk").html(filterXSS($common.valueWithDefault(metric.vulnerableProjects, "0")));
    $("#statTotalProjects").html(filterXSS($common.valueWithDefault(metric.projects, "0")));
    $("#statVulnerableProjects").html(filterXSS($common.valueWithDefault(metric.vulnerableProjects, "0")));
    $("#statTotalDependencies").html(filterXSS($common.valueWithDefault(metric.dependencies, "0")));
    $("#statVulnerableDependencies").html(filterXSS($common.valueWithDefault(metric.vulnerableDependencies, "0")));
    $("#statTotalComponents").html(filterXSS($common.valueWithDefault(metric.components, "0")));
    $("#statVulnerableComponents").html(filterXSS($common.valueWithDefault(metric.vulnerableComponents, "0")));
    $("#statPortfolioVulnerabilities").html(filterXSS($common.valueWithDefault(metric.vulnerabilities, "0")));
    $("#statPortfolioSuppressed").html(filterXSS($common.valueWithDefault(metric.suppressed, "0")));
    $("#statLastMeasurement").html(filterXSS($common.formatTimestamp(metric.lastOccurrence, true)));
}

function getDashboardData() {
    d3.selectAll(".nvtooltip").remove();
    $rest.getPortfolioMetrics(90, function(metrics) {
        $chart.createSeverityTrendChart(metrics, "portfoliochart", "Portfolio Vulnerabilities");
        $chart.createAffectedVsTotalTrendChart(metrics, "projectchart", "Projects", "vulnerableProjects", "projects", "Vulnerable Projects", "Total Projects");
        $chart.createAffectedVsTotalTrendChart(metrics, "dependencychart", "Dependencies", "vulnerableDependencies", "dependencies", "Vulnerable Dependencies", "Total Dependencies");
        $chart.createAffectedVsTotalTrendChart(metrics, "componentchart", "Components", "vulnerableComponents", "components", "Vulnerable Components", "Total Components");
        populateProgressBars(metrics);
        updateStats(metrics);
    });
    $rest.getVulnerabilityMetrics(function(metrics) {
        $chart.createVulnerabilityChart(metrics, "vulnerabilitychart", "Vulnerabilities", 10);
    });
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready.
 */
$(document).ready(function () {
    getDashboardData();

    // Listen for refresh icon to be triggered
    $("#refresh").on("click", function() {
        $rest.refreshPortfolioMetrics(function() {
            $("#statLastMeasurement").html("Refresh triggered");
            $common.displayInfoModal("A refresh has been requested. The amount of time required to refresh is dependant on the amount of background processing currently being performed and the size of the data-set being refreshed.")
        });
    });

});
