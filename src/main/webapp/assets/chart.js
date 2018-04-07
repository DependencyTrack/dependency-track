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

const $chart = function() {
};

$chart.days = function days(num) {
    return num*60*60*1000*24
};

/**
 * Creates a chart with the total number of critical, high, medium, and low severity findings/vulnerabilities.
 */
$chart.createSeverityTrendChart = function createSeverityTrendChart(metrics, divId, title) {
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
        chart.yAxis.axisLabel(title).tickFormat(d3.format("d"));
        d3.selectAll("#" + divId + " > *").remove();
        d3.select("#" + divId).append("svg").datum(data).call(chart);
        nv.utils.windowResize(chart.update);
        return chart;
    });
};

/**
 * Creates a line chart with two lines - a total number of something, and an affected number of something.
 */
$chart.createAffectedVsTotalTrendChart = function createAffectedVsTotalTrendChart(metrics, divId, title, affectedField, totalField, affectedLabel, totalLabel) {
    function prepareChartData(metrics) {
        let totalArray = [];
        let affectedArray = [];
        for (let i = 0; i < metrics.length; i++) {
            totalArray.push({x: new Date(metrics[i].firstOccurrence), y: eval("metrics[i]." + totalField)});
            affectedArray.push({x: new Date(metrics[i].firstOccurrence), y: eval("metrics[i]." + affectedField)});

            if (i === metrics.length - 1) {
                totalArray.push({x: new Date(metrics[i].lastOccurrence), y: eval("metrics[i]." +totalField)});
                affectedArray.push({x: new Date(metrics[i].lastOccurrence), y: eval("metrics[i]." +affectedField)});
            }
        }
        return [
            {
                area: true,
                values: totalArray,
                key: totalLabel,
                color: "#444444",
                fillOpacity: .1
            },
            {
                area: true,
                values: affectedArray,
                key: affectedLabel,
                color: "#357abd",
                fillOpacity: .1
            }
        ];
    }

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
        chart.yAxis.axisLabel(title).tickFormat(d3.format("d"));
        d3.selectAll("#" + divId + " > *").remove();
        d3.select("#" + divId).append("svg").datum(data).call(chart);
        nv.utils.windowResize(chart.update);
        return chart;
    });
};

/**
 * Creates a bar chart that graphs the total number of vulnerabilities for the past x years.
 */
$chart.createVulnerabilityChart = function createVulnerabilityChart(metrics, divId, title, years) {
    function prepareChartData(metrics) {
        let vulnerabilities = [];
        let beginYear = new Date().getFullYear() - years; // go (x) years back only
        for (let i = 0; i < metrics.length; i++) {
            let metric = metrics[i];
            if (!metric.hasOwnProperty("month") && metric.year >= beginYear) {
                vulnerabilities.push({label: metric.year, value: metric.count});
            }
        }
        return [
            {
                values: vulnerabilities,
                key: title,
                color: "#444444",
                fillOpacity: 1
            }
        ];
    }

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
        d3.selectAll("#" + divId + " > *").remove();
        d3.select("#" + divId).append("svg").datum(data).call(chart);
        nv.utils.windowResize(chart.update);
        return chart;
    });
};