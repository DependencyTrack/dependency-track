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
 * Called by bootstrap table to format the data in the projects table.
 */
function formatProjectsTable(res) {
    let projectsTable = $("#projectsTable");
    for (let i=0; i<res.length; i++) {
        let projecturl = "../project/?uuid=" + res[i].uuid;
        res[i].projecthref = "<a href=\"" + projecturl + "\">" + filterXSS(res[i].name) + "</a>";

        $rest.getProjectCurrentMetrics(res[i].uuid, function (data) {
            res[i].vulnerabilities = $common.generateSeverityProgressBar(data.critical, data.high, data.medium, data.low);
            projectsTable.bootstrapTable('updateRow', {
                index: i,
                row: res[i]
            });
        });
    }
    return res;
}

function projectCreated(data) {
    $("#projectsTable").bootstrapTable("refresh", {silent: true});
}

/**
 * Clears all the input fields from the modal.
 */
function clearInputFields() {
    $("#createProjectNameInput").val("");
    $("#createProjectVersionInput").val("");
    $("#createProjectDescriptionInput").val("");
    $("#createProjectTagsInput").val("");
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
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {
    let tag = $.getUrlVar("tag");
    if (tag) {
        $("#projectsTable").bootstrapTable("refresh", {
            url: $rest.contextPath() + URL_PROJECT + "/tag/" + encodeURIComponent(tag),
            silent: true
        });
    }

    $rest.getPortfolioCurrentMetrics(function(metrics) {
        updateStats(metrics);
    });

    // Initialize all tooltips
    $('[data-toggle="tooltip"]').tooltip();

    // Listen for if the button to create a project is clicked
    $("#createProjectCreateButton").on("click", function() {
        const name = $("#createProjectNameInput").val();
        const version = $("#createProjectVersionInput").val();
        const description = $("#createProjectDescriptionInput").val();
        const tags = $common.csvStringToObjectArray($("#createProjectTagsInput").val());
        $rest.createProject(name, version, description, tags, projectCreated);
        clearInputFields();
    });

    // When modal closes, clear out the input fields
    $("#modalCreateProject").on("hidden.bs.modal", function() {
        $("#createProjectNameInput").val("");
    });

});