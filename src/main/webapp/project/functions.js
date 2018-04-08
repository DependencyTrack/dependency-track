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
 * Called by bootstrap table to format the data in the dependencies table.
 */
function formatDependenciesTable(res) {
    let dependenciesTable = $("#dependenciesTable");
    for (let i=0; i<res.length; i++) {
        let componenturl = "../component/?uuid=" + res[i].component.uuid;
        res[i].componenthref = "<a href=\"" + componenturl + "\">" + filterXSS(res[i].component.name)+ "</a>";
        res[i].component.version = filterXSS(res[i].component.version);
        res[i].component.group = filterXSS(res[i].component.group);

        if (res[i].component.hasOwnProperty("resolvedLicense")) {
            let licenseurl = "../license/?licenseId=" + res[i].component.resolvedLicense.licenseId;
            res[i].component.license = "<a href=\"" + licenseurl + "\">" + filterXSS(res[i].component.resolvedLicense.licenseId) + "</a>";
        }

        $rest.getComponentCurrentMetrics(res[i].component.uuid, function (data) {
            res[i].component.vulnerabilities = $common.generateSeverityProgressBar(data.critical, data.high, data.medium, data.low);
            dependenciesTable.bootstrapTable("updateRow", {
                index: i,
                row: res[i].component
            });
        });
    }
    return res;
}

/**
 * Called by bootstrap table to format the data in the components table (when adding a new dependency from an existing component).
 */
function formatComponentsTable(res) {
    for (let i=0; i<res.length; i++) {
        res[i].name = filterXSS(res[i].name);
        res[i].version = filterXSS(res[i].version);
        res[i].group = filterXSS(res[i].group);
    }
    return res;
}

/**
 * Called by bootstrap table to format the data in the findings table.
 */
function formatFindingsTable(res) {
    for (let i=0; i<res.length; i++) {
        let vulnurl = "../vulnerability/?source=" + res[i].source + "&vulnId=" + res[i].vulnId;
        res[i].vulnerabilityhref = $common.formatSourceLabel(res[i].source) + " <a href=\"" + vulnurl + "\">" + filterXSS(res[i].vulnId) + "</a>";

        if (res[i].hasOwnProperty("cwe")) {
            res[i].cwefield = "CWE-" + res[i].cwe.cweId + " " + res[i].cwe.name;
        }

        if (res[i].hasOwnProperty("severity")) {
            res[i].severityLabel = $common.formatSeverityLabel(res[i].severity);
        }
    }
    return res;
}

/**
 * Given a comma-separated string of tags, creates an
 * array of tag objects.
 */
function tagsStringToObjectArray(tagsString) {
    let tagsArray = [];
    if (!$common.isEmpty(tagsString)) {
        let tmpArray = tagsString.split(",");
        for (let i in tmpArray) {
            tagsArray.push({name: tmpArray[i]});
        }
    }
    return tagsArray;
}

/**
 * Clears all the input fields from the modal.
 */
function clearInputFields() {
    $("#createComponentNameInput").val("");
    $("#createComponentVersionInput").val("");
    $("#createComponentGroupInput").val("");
    $("#createComponentDescriptionInput").val("");
    $("#createComponentLicenseSelect").val("");
}

function populateProjectData(data) {

    // Retrieve the list of project versions and determine which one should be selected
    $rest.getProjectVersions(data.name, function (versionData) {
        let select = $("#projectVersionSelect");
        $.each(versionData, function() {
            let escapedProjectVersion = filterXSS(this.version);
            if (this.version === data.version) {
                select.append($("<option selected=\"selected\"/>").val(this.uuid).text(escapedProjectVersion));
            } else {
                select.append($("<option />").val(this.uuid).text(escapedProjectVersion));
            }
        });
        select.selectpicker('refresh');
    });

    let escapedProjectName = filterXSS(data.name);
    let escapedProjectVersion = filterXSS(data.version);
    let escapedProjectDescription = filterXSS(data.description);

    $("#projectNameInput").val(data.name);
    $("#projectVersionInput").val(data.version);
    $("#projectDescriptionInput").val(data.description);

    $("#projectTitle").html(escapedProjectName);
    if (data.version) {
        $("#projectVersion").html(" &#x025B8; " + escapedProjectVersion);
    } else {
        $("#projectVersion").empty();
    }
    if (data.tags) {
        let html = "";
        let tagsInput = $("#projectTagsInput");
        for (let i=0; i<data.tags.length; i++) {
            let tag = data.tags[i].name;
            html += `<a href="../projects/?tag=${encodeURIComponent(tag)}"><span class="badge tag-standalone">${filterXSS(tag)}</span></a>`;
            tagsInput.tagsinput("add", tag);
        }
        $("#tags").html(html);
    } else {
        $("#tags").empty();
    }
    if (data.properties) {
        $("#projectPropertiesTable").css("display", "table");
        let html = "";
        for (let i=0; i<data.properties.length; i++) {
            let property = data.properties[i];
            html += `<tr><td>${filterXSS(property.key)}</td><td>${filterXSS(property.value)}</td></tr>`;
        }
        $("#projectPropertiesTableData").html(html);
    } else {
        $("#projectPropertiesTableData").empty();
        $("#projectPropertiesTable").css("display", "none");
    }
}

function populateLicenseData(data) {
    let select = $("#createComponentLicenseSelect");
    $.each(data, function() {
        select.append($("<option />").val(this.licenseId).text(this.name));
    });
    select.selectpicker("refresh");
}

function populateMetrics(metric) {
    $("#metricCritical").html(filterXSS($common.valueWithDefault(metric.critical, "0")));
    $("#metricHigh").html(filterXSS($common.valueWithDefault(metric.high, "0")));
    $("#metricMedium").html(filterXSS($common.valueWithDefault(metric.medium, "0")));
    $("#metricLow").html(filterXSS($common.valueWithDefault(metric.low, "0")));
    $("#metricIrs").html(filterXSS($common.valueWithDefault(metric.inheritedRiskScore, "0")));

    $("#statTotalComponents").html(filterXSS($common.valueWithDefault(metric.components, "0")));
    $("#statVulnerableComponents").html(filterXSS($common.valueWithDefault(metric.vulnerableComponents, "0")));
    $("#statVulnerabilities").html(filterXSS($common.valueWithDefault(metric.vulnerabilities, "0")));
    $("#statSuppressed").html(filterXSS($common.valueWithDefault(metric.suppressed, "0")));
    $("#statLastMeasurement").html(filterXSS($common.formatTimestamp(metric.lastOccurrence, true)));
}

function getTrendData() {
    let uuid = $.getUrlVar("uuid");
    d3.selectAll(".nvtooltip").remove();
    $rest.getProjectMetrics(uuid, 90, function(metrics) {
        $chart.createSeverityTrendChart(metrics, "projectchart", "Project Vulnerabilities");
        $chart.createAffectedVsTotalTrendChart(metrics, "componentchart", "Components", "vulnerableComponents", "components", "Vulnerable Components", "Total Components");
    });
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {
    let uuid = $.getUrlVar("uuid");

    const token = $auth.decodeToken($auth.getToken());
    if ($auth.hasPermission($auth.VULNERABILITY_ANALYSIS, token)) {
        const findingsUrl = $rest.contextPath() + URL_FINDING + "/project/" + uuid;
        $("#findingsTable").bootstrapTable("refresh", {url: findingsUrl, silent: true});
    }

    $rest.getProject(uuid, populateProjectData);
    $rest.getLicenses(populateLicenseData);
    $rest.getProjectCurrentMetrics(uuid, populateMetrics);

    // Listen for when the button to add a dependency from a new component is clicked
    $("#addDependencyFromNewButton").on("click", function () {
        const name = $("#createComponentNameInput").val();
        const version = $("#createComponentVersionInput").val();
        const group = $("#createComponentGroupInput").val();
        const description = $("#createComponentDescriptionInput").val();
        const licenseId = $("#createComponentLicenseSelect").val();
        $rest.createComponentMinimalFields(name, version, group, description, licenseId, function(data) {
            $rest.addDependency(uuid, [data.uuid], null, function() {
                $("#dependenciesTable").bootstrapTable("refresh", {silent: true});
            });
        });
        $("#modalAddDependency").modal("hide");
        $("#componentsTable").bootstrapTable("uncheckAll");
        clearInputFields();
    });

    // Listen for when the button to add a dependency from an existing component is clicked
    $("#addDependencyFromExistingButton").on("click", function () {
        let componentsTable = $("#componentsTable");
        let selections = componentsTable.bootstrapTable("getSelections");
        let componentUuids = [];
        for (let i=0; i<selections.length; i++) {
            componentUuids[i] = selections[i].uuid;
        }
        $rest.addDependency(uuid, componentUuids, null, function() {
            $("#dependenciesTable").bootstrapTable("refresh", {silent: true});
        });
        $("#modalAddDependency").modal("hide");
        componentsTable.bootstrapTable("uncheckAll");
        clearInputFields();
    });

    // When modal closes, clear out the input fields
    $("#modalAddDependency").on("hidden.bs.modal", function () {
        clearInputFields();
    });

    // Listen for when the button to remove a dependency is clicked
    $("#removeDependencyButton").on("click", function () {
        let dependenciesTable = $("#dependenciesTable");
        let selections = dependenciesTable.bootstrapTable("getSelections");
        let componentUuids = [];
        for (let i=0; i<selections.length; i++) {
            componentUuids[i] = selections[i].uuid;
        }
        $rest.removeDependency(uuid, componentUuids, function() {
            $("#dependenciesTable").bootstrapTable("refresh", {silent: true});
        });
        dependenciesTable.bootstrapTable("uncheckAll");
    });

    $("#updateProjectButton").on("click", function () {
        let name = $("#projectNameInput").val();
        let version = $("#projectVersionInput").val();
        let description = $("#projectDescriptionInput").val();
        let tags = $common.csvStringToObjectArray($("#projectTagsInput").val());
        $rest.updateProject(uuid, name, version, description, tags, function() {
            $rest.getProject(uuid, populateProjectData);
        });
    });

    $("#deleteProjectButton").on("click", function () {
        $rest.deleteProject(uuid, function() {
            window.location.href = "../projects";
        });
    });

    $("#projectVersionSelect").on("change", function () {
        let uuid = $("#projectVersionSelect").val();
        window.location.href = "?uuid=" + uuid;
    });

    getTrendData();

    // Listen for refresh icon to be triggered
    $("#refresh").on("click", function() {
        $rest.refreshProjectMetrics(uuid, function() {
            $("#statLastMeasurement").html("Refresh triggered");
            $common.displayInfoModal("A refresh has been requested. The amount of time required to refresh is dependant on the amount of background processing currently being performed and the size of the data-set being refreshed.")
        });
    });
});