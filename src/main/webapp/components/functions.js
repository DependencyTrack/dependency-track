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
    $("#componentNameInput").val("");
    $("#componentVersionInput").val("");
    $("#componentGroupInput").val("");
    $("#componentDescriptionInput").val("");
    $("#componentLicenseSelect").val("");
    $("#componentFilenameInput").val("");
    $("#componentPurlInput").val("");
    $("#componentCpeInput").val("");
    $("#componentCopyrightInput").val("");
    $("#componentMd5Input").val("");
    $("#componentSha1Input").val("");
    $("#componentSha256Input").val("");
    $("#componentSha512Input").val("");
    $("#componentSha3256Input").val("");
    $("#componentSha3512Input").val("");
}

/**
 * Populates select/dropdown with list of all licenses.
 */
function populateLicenseData(data) {
    let select = $("#componentLicenseSelect");
    $.each(data, function() {
        select.append($("<option />").val(this.licenseId).text(this.name));
    });
    select.selectpicker('refresh');
}

function updateStats(metric) {
    $("#statTotalProjects").html(metric.projects);
    $("#statVulnerableProjects").html(metric.vulnerableProjects);
    $("#statTotalComponents").html(metric.components);
    $("#statVulnerableComponents").html(metric.vulnerableComponents);
    $("#statPortfolioVulnerabilities").html(metric.vulnerabilities);
    $("#statLastMeasurement").html(filterXSS($common.formatTimestamp(metric.lastOccurrence, true)));
    $("#statInheritedRiskScore").html(metric.inheritedRiskScore);
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
    $("#componentCreateButton").on("click", function() {
        const name = $common.valueWithDefault($("#componentNameInput").val(), null);
        const version = $common.valueWithDefault($("#componentVersionInput").val(), null);
        const group = $common.valueWithDefault($("#componentGroupInput").val(), null);
        const description = $common.valueWithDefault($("#componentDescriptionInput").val(), null);
        const license = $common.valueWithDefault($("#componentLicenseSelect").val(), null);
        const filename = $common.valueWithDefault($("#componentFilenameInput").val(), null);
        const classifier = $common.valueWithDefault($("#componentClassifierInput").val(), null);
        const purl = $common.valueWithDefault($("#componentPurlInput").val(), null);
        const cpe = $common.valueWithDefault($("#componentCpeInput").val(), null);
        const copyright = $common.valueWithDefault($("#componentCopyrightInput").val(), null);
        const md5 = $common.valueWithDefault($("#componentMd5Input").val(), null);
        const sha1 = $common.valueWithDefault($("#componentSha1Input").val(), null);
        const sha256 = $common.valueWithDefault($("#componentSha256Input").val(), null);
        const sha512 = $common.valueWithDefault($("#componentSha512Input").val(), null);
        const sha3_256 = $common.valueWithDefault($("#componentSha3256Input").val(), null);
        const sha3_512 = $common.valueWithDefault($("#componentSha3512Input").val(), null);

        $rest.createComponent(name, version, group, description, license,
            filename, classifier, purl, cpe, copyright,
            md5, sha1, sha256, sha512, sha3_256, sha3_512, componentCreated);
        clearInputFields();
    });

    // When modal closes, clear out the input fields
    $("#modalCreateComponent").on("hidden.bs.modal", function() {
        clearInputFields();
    });

    // Restrict characters that can be typed into hash inputs
    $(".hash-input").keypress( function(e) {
        return ("acbdefABCDEF0123456789").indexOf(String.fromCharCode(e.which)) >= 0;
    });

});