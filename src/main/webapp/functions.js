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

function createPortfolioVulnerabilityChart(metrics) {
    let data = prepareChartData(metrics);

    function days(num) {
        return num*60*60*1000*24
    }

    nv.addGraph(function() {
        let chart = nv.models.lineChart()
            .options({
                duration: 300,
                //showLegend: false,
                useInteractiveGuideline: true
            })
        ;
        chart.legend.vers("furious");
        chart.xAxis
            .tickFormat(function(d) { return d3.time.format("%b %d")(new Date(d)); })
            .staggerLabels(true)
        ;
        chart.yAxis.axisLabel("Portfolio Vulnerabilities").tickFormat(d3.format("d"));
        d3.selectAll("#portfoliochart > *").remove();
        d3.select("#portfoliochart").append("svg").datum(data).call(chart);
        nv.utils.windowResize(chart.update);
        return chart;
    });

    function prepareChartData(metrics) {
        let critical = [];
        let high = [];
        let medium = [];
        let low = [];
        for (let i = 0; i < metrics.length; i++) {
            critical.push({x: new Date(metrics[i].firstOccurrence), y: metrics[i].critical});
            high.push({x: new Date(metrics[i].firstOccurrence), y: metrics[i].high});
            medium.push({x: new Date(metrics[i].firstOccurrence), y: metrics[i].medium});
            low.push({x: new Date(metrics[i].firstOccurrence), y: metrics[i].low});

            if (i === metrics.length - 1) {
                critical.push({x: new Date(metrics[i].lastOccurrence), y: metrics[i].critical});
                high.push({x: new Date(metrics[i].lastOccurrence), y: metrics[i].high});
                medium.push({x: new Date(metrics[i].lastOccurrence), y: metrics[i].medium});
                low.push({x: new Date(metrics[i].lastOccurrence), y: metrics[i].low});
            }
        }
        return [
            {
                area: true,
                values: critical,
                key: "Critical",
                color: "#d43f3a",
                fillOpacity: .1
            },
            {
                area: true,
                values: high,
                key: "High",
                color: "#d4663a",
                fillOpacity: .1
            },
            {
                area: true,
                values: medium,
                key: "Medium",
                color: "#fdc431",
                fillOpacity: .1
            },
            {
                area: true,
                values: low,
                key: "Low",
                color: "#4cae4c",
                fillOpacity: .1
            },

        ];
    }
}

function createProjectVulnerabilityChart(metrics) {
    let data = prepareChartData(metrics);

    nv.addGraph(function() {
        let chart = nv.models.lineChart()
            .options({
                duration: 300,
                //showLegend: false,
                useInteractiveGuideline: true
            })
        ;
        chart.legend.vers("furious");
        chart.xAxis
            .tickFormat(function(d) { return d3.time.format("%b %d")(new Date(d)); })
            .staggerLabels(true)
        ;
        chart.yAxis.axisLabel("Projects").tickFormat(d3.format("d"));
        d3.selectAll("#projectchart > *").remove();
        d3.select("#projectchart").append("svg").datum(data).call(chart);
        nv.utils.windowResize(chart.update);
        return chart;
    });

    function prepareChartData(metrics) {
        let projects = [];
        let vulnerableProjects = [];
        for (let i = 0; i < metrics.length; i++) {
            projects.push({x: new Date(metrics[i].firstOccurrence), y: metrics[i].projects});
            vulnerableProjects.push({x: new Date(metrics[i].firstOccurrence), y: metrics[i].vulnerableProjects});

            if (i === metrics.length - 1) {
                projects.push({x: new Date(metrics[i].lastOccurrence), y: metrics[i].projects});
                vulnerableProjects.push({x: new Date(metrics[i].lastOccurrence), y: metrics[i].vulnerableProjects});
            }
        }
        return [
            {
                area: true,
                values: projects,
                key: "Total Projects",
                color: "#444444",
                fillOpacity: .1
            },
            {
                area: true,
                values: vulnerableProjects,
                key: "Vulnerable Projects",
                color: "#357abd",
                fillOpacity: .1
            }
        ];
    }
}

function createComponentVulnerabilityChart(metrics) {
    let data = prepareChartData(metrics);

    nv.addGraph(function() {
        let chart = nv.models.lineChart()
            .options({
                duration: 300,
                //showLegend: false,
                useInteractiveGuideline: true
            })
        ;
        chart.legend.vers("furious");
        chart.xAxis
            .tickFormat(function(d) { return d3.time.format("%b %d")(new Date(d)); })
            .staggerLabels(true)
        ;
        chart.yAxis.axisLabel("Components").tickFormat(d3.format("d"));
        d3.selectAll("#componentchart > *").remove();
        d3.select("#componentchart").append("svg").datum(data).call(chart);
        nv.utils.windowResize(chart.update);
        return chart;
    });

    function prepareChartData(metrics) {
        let components = [];
        let vulnerableComponents = [];
        for (let i = 0; i < metrics.length; i++) {
            components.push({x: new Date(metrics[i].firstOccurrence), y: metrics[i].components});
            vulnerableComponents.push({x: new Date(metrics[i].firstOccurrence), y: metrics[i].vulnerableComponents});

            if (i === metrics.length - 1) {
                components.push({x: new Date(metrics[i].lastOccurrence), y: metrics[i].components});
                vulnerableComponents.push({x: new Date(metrics[i].lastOccurrence), y: metrics[i].vulnerableComponents});
            }
        }
        return [
            {
                area: true,
                values: components,
                key: "Total Components",
                color: "#444444",
                fillOpacity: .1
            },
            {
                area: true,
                values: vulnerableComponents,
                key: "Vulnerable Components",
                color: "#357abd",
                fillOpacity: .1
            }
        ];
    }
}

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
    console.log(metric.vulnerableProjects);
    $("#projectsAtRisk").html(filterXSS($common.valueWithDefault(metric.vulnerableProjects, "0")));
    $("#statTotalProjects").html(filterXSS($common.valueWithDefault(metric.projects, "0")));
    $("#statVulnerableProjects").html(filterXSS($common.valueWithDefault(metric.vulnerableProjects, "0")));
    $("#statTotalComponents").html(filterXSS($common.valueWithDefault(metric.components, "0")));
    $("#statVulnerableComponents").html(filterXSS($common.valueWithDefault(metric.vulnerableComponents, "0")));
    $("#statPortfolioVulnerabilities").html(filterXSS($common.valueWithDefault(metric.vulnerabilities, "0")));
    $("#statLastMeasurement").html(filterXSS($common.formatTimestamp(metric.lastOccurrence, true)));
}

function createVulnerabilityChart(metrics) {
    let data = prepareChartData(metrics);
    nv.addGraph(function() {
        let chart = nv.models.discreteBarChart()
            .x(function(d) { return d.label })
            .y(function(d) { return d.value })
            .valueFormat(d3.format(".0f"))
            .color(["#357abd"])
            .staggerLabels(false)
            .duration(300)
        ;
        chart.yAxis.tickFormat(d3.format(",f"));
        d3.selectAll("#vulnerabilitychart > *").remove();
        d3.select("#vulnerabilitychart").append("svg").datum(data).call(chart);
        nv.utils.windowResize(chart.update);
        return chart;
    });

    function prepareChartData(metrics) {
        let vulnerabilities = [];
        let beginYear = new Date().getFullYear() - 10; // go ten years back only
        for (let i = 0; i < metrics.length; i++) {
            let metric = metrics[i];
            if (!metric.hasOwnProperty("month") && metric.year >= beginYear) {
                vulnerabilities.push({label: metric.year, value: metric.count});
            }
        }
        return [
            {
                values: vulnerabilities,
                key: "Vulnerabilities",
                color: "#444444",
                fillOpacity: 1
            }
        ];
    }

}

function getDashboardData() {
    d3.selectAll(".nvtooltip").remove();
    $rest.getPortfolioMetrics(90, function(metrics) {
        createPortfolioVulnerabilityChart(metrics);
        createProjectVulnerabilityChart(metrics);
        createComponentVulnerabilityChart(metrics);
        populateProgressBars(metrics);
        updateStats(metrics);
    });
    $rest.getVulnerabilityMetrics(createVulnerabilityChart);
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready.
 */
$(document).ready(function () {
    getDashboardData();
    setInterval(getDashboardData, 30 * 1000); // Refresh dashboard every 30 seconds

    // Listen for refresh icon to be triggered
    $("#refresh").on("click", function() {
        $rest.refreshPortfolioMetrics(function() {
            $("#statLastMeasurement").html("Refresh triggered");
            $common.displayInfoModal("A refresh has been requested. The amount of time required to refresh is dependant on the amount of background processing currently being performed and the size of the data-set being refreshed.")
        });
    });

});
