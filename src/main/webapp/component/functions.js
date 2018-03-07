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

    $("#componentFilenameInput").val(data.filename);
    $("#componentPurlInput").val(data.purl);
    $("#componentCpeInput").val(data.cpe);
    $("#componentCopyrightInput").val(data.copyright);
    $("#componentMd5Input").val(data.md5);
    $("#componentSha1Input").val(data.sha1);
    $("#componentSha256Input").val(data.sha256);
    $("#componentSha512Input").val(data.sha512);
    $("#componentSha3256Input").val(data.sha3_256);
    $("#componentSha3512Input").val(data.sha3_512);


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

    // Determine which classifier should be selected
    $("#componentClassifierInput option[value='" + data.classifier + "']").attr("selected", "selected");
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
    $("#metricCritical").html(data.critical);
    $("#metricHigh").html(data.high);
    $("#metricMedium").html(data.medium);
    $("#metricLow").html(data.low);
    $("#metricIrs").html(data.inheritedRiskScore);
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {
    let uuid = $.getUrlVar('uuid');

    $rest.getComponent(uuid, populateComponentData);
    $rest.getComponentCurrentMetrics(uuid, populateMetrics);

    $("#updateComponentButton").on("click", function () {
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

        $rest.updateComponent(uuid, name, version, group, description, license,
            filename, classifier, purl, cpe, copyright,
            md5, sha1, sha256, sha512, sha3_256, sha3_512,
            function() {
                $rest.getComponent(uuid, populateComponentData);
            }
        );
    });

    $("#deleteComponentButton").on("click", function () {
        $rest.deleteComponent(uuid, function() {
            window.location.href = "../components";
        });
    });
});