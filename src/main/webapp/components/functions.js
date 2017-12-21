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
 * Called by bootstrap table to format the data in the components table.
 */
function formatComponentsTable(res) {
    let componentsTable = $("#componentsTable");
    for (let i=0; i<res.length; i++) {
        let componenturl = "../component/?uuid=" + res[i].uuid;
        res[i].componenthref = "<a href=\"" + componenturl + "\">" + filterXSS(res[i].name) + "</a>";
        res[i].version = filterXSS(res[i].version);
        res[i].group = filterXSS(res[i].group);

        if (res[i].hasOwnProperty("resolvedLicense")) {
            let licenseurl = "../license/?licenseId=" + res[i].resolvedLicense.licenseId;
            res[i].license = "<a href=\"" + licenseurl + "\">" + filterXSS(res[i].resolvedLicense.licenseId) + "</a>";
        }

        $rest.getComponentCurrentMetrics(res[i].uuid, function (data) {
            res[i].vulnerabilities = $common.generateSeverityProgressBar(data.critical, data.high, data.medium, data.low);
            componentsTable.bootstrapTable('updateRow', {
                index: i,
                row: res[i]
            });
        });
    }
    return res;
}

function componentCreated(data) {
    $("#componentsTable").bootstrapTable("refresh", {silent: true});
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

/**
 * Populates select/dropdown with list of all licenses.
 */
function populateLicenseData(data) {
    let select = $("#createComponentLicenseSelect");
    $.each(data, function() {
        select.append($("<option />").val(this.licenseId).text(this.name));
    });
    select.selectpicker('refresh');
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
    $rest.getLicenses(populateLicenseData);

    // Listen for if the button to create a project is clicked
    $("#createComponentCreateButton").on("click", function() {
        const name = $("#createComponentNameInput").val();
        const version = $("#createComponentVersionInput").val();
        const group = $("#createComponentGroupInput").val();
        const description = $("#createComponentDescriptionInput").val();
        const license = $("#createComponentLicenseSelect").val();
        $rest.createComponent(name, version, group, description, license, componentCreated);
        clearInputFields();
    });

    // When modal closes, clear out the input fields
    $("#modalCreateComponent").on("hidden.bs.modal", function() {
        clearInputFields();
    });

});