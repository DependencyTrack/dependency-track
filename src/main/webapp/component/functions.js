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

function populateComponentData(data) {
    let escapedComponentName = filterXSS(data.name);
    let escapedComponentVersion = filterXSS(data.version);
    let escapedComponentDescription = filterXSS(data.description);

    $("#componentNameInput").val(data.name);
    $("#componentVersionInput").val(data.version);
    $("#componentGroupInput").val(data.group);
    $("#componentDescriptionInput").val(data.description);

    $("#componentName").html(escapedComponentName);
    if (data.version) {
        $("#componentVersion").html(" &#x025B8; " + escapedComponentVersion);
    } else {
        $("#componentVersion").empty();
    }
    if (data.resolvedLicense && data.resolvedLicense.name) {
        $("#componentLicense").html(filterXSS(data.resolvedLicense.name));
    } else if (data.license) {
        $("#componentLicense").html(filterXSS(data.license));
    } else {
        $("#componentLicense").empty();
    }

    // Retrieve the list of licenses and determine which one should be selected
    $rest.getLicenses(function (licenseData) {
        let select = $("#componentLicenseSelect");
        $.each(licenseData, function() {
            if (data.resolvedLicense && data.resolvedLicense.licenseId && this.licenseId === data.resolvedLicense.licenseId) {
                select.append($("<option selected=\"selected\"/>").val(this.licenseId).text(this.name));
            } else {
                select.append($("<option />").val(this.licenseId).text(this.name));
            }
        });
        select.selectpicker('refresh');
    });
}

function populateLicenseData(data) {
    let select = $("#componentLicenseSelect");
    $.each(data, function() {
        select.append($("<option />").val(this.licenseId).text(this.name));
    });
    select.selectpicker('refresh');
}

function formatVulnerabilitiesTable(res) {
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

function formatProjectsTable(res) {
    for (let i=0; i<res.length; i++) {
        let projecturl = "../project/?uuid=" + res[i].project.uuid;
        res[i].project.projecthref = "<a href=\"" + projecturl + "\">" + filterXSS(res[i].project.name) + "</a>";
        res[i].project.version = filterXSS(res[i].project.version);
    }
    return res;
}

function populateMetrics(data) {
    $("#metricCritical").html(filterXSS(data.critical));
    $("#metricHigh").html(filterXSS(data.high));
    $("#metricMedium").html(filterXSS(data.medium));
    $("#metricLow").html(filterXSS(data.low));
    $("#metricIrs").html(filterXSS(data.inheritedRiskScore));
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {
    let uuid = $.getUrlVar('uuid');

    $rest.getComponent(uuid, populateComponentData);
    $rest.getComponentCurrentMetrics(uuid, populateMetrics);

    $("#updateComponentButton").on("click", function () {
        let name = $("#componentNameInput").val();
        let version = $("#componentVersionInput").val();
        let description = $("#componentDescriptionInput").val();
        let group = $("#componentGroupInput").val();
        let license = $("#componentLicenseSelect").val();
        $rest.updateComponent(uuid, name, version, group, description, license, function() {
            $rest.getComponent(uuid, populateComponentData);
        });
    });

    $("#deleteComponentButton").on("click", function () {
        $rest.deleteComponent(uuid, function() {
            window.location.href = "../components";
        });
    });
});