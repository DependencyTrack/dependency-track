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

/**
 * Populates select/dropdown with list of all CWEs.
 */
function populateCweData(data) {
    let select = $("#vulnerabilityCweSelect");
    $.each(data, function() {
        select.append($("<option />").val(this.cweId).text("CWE-" + this.cweId + ": "+ this.name));
    });
    select.selectpicker('refresh');
}

function vulnerabilityCreated(data) {
    $("#componentsTable").bootstrapTable("refresh", {silent: true});
}

/**
 * Clears all the input fields from the modal.
 */
function clearInputFields() {
    $("#vulnerabilityVulnIdInput").val("");
    $("#vulnerabilityTitleInput").val("");
    $("#vulnerabilitySubtitleInput").val("");
    $("#vulnerabilityDescriptionInput").val("");
    $("#vulnerabilityRecommendationInput").val("");
    $("#vulnerabilityReferencesInput").val("");
    $("#vulnerabilityCreditsInput").val("");
    //$("#vulnerabilityCreatedInput").val("");
    //$("#vulnerabilityPublishedInput").val("");
    //$("#vulnerabilityUpdatedInput").val("");
    $("#vulnerabilityCweSelect").val("");
    //todo calculator buttons
    $("#vulnerabilityVulnerableVersionsInput").val("");
    $("#vulnerabilityPatchedVersionsInput").val("");
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


function updateGauge(elmId, score) {
    $(elmId).html($common.toHtml(score));
    $(elmId + "Percent").data("easyPieChart").update(score * 10);
}

/**
 * Returns the value from a CVSSv2 or CVSSv3 button by the buttons 'name'.
 */
function getCvssButtonValue(name) {
    let value = null;
    $("button[name=" + name + "]").each(function() {
        if ($(this).hasClass("active")) {
            value = $(this).attr("value");
        }
    });
    return value;
}

/**
 * Generates a CVSSV2 Vector from the form controls. Returns null if all required
 * controls do not have a value.
 */
function generateCvssV2Vector() {
    let av = getCvssButtonValue("v2av");
    let ac = getCvssButtonValue("v2ac");
    let au = getCvssButtonValue("v2au");
    let c = getCvssButtonValue("v2c");
    let i = getCvssButtonValue("v2i");
    let a = getCvssButtonValue("v2a");
    if (av != null && ac != null && au != null && c != null && i != null && a != null) {
        return "(AV:"+av+"/AC:"+ac+"/Au:"+au+"/C:"+c+"/I:"+i+"/A:"+a+")";
    }
    return null;
}

/**
 * Generates a CVSSV3 Vector from the form controls. Returns null if all required
 * controls do not have a value.
 */
function generateCvssV3Vector() {
    let av = getCvssButtonValue("v3av");
    let ac = getCvssButtonValue("v3ac");
    let pr = getCvssButtonValue("v3pr");
    let ui = getCvssButtonValue("v3ui");
    let s = getCvssButtonValue("v3s");
    let c = getCvssButtonValue("v3c");
    let i = getCvssButtonValue("v3i");
    let a = getCvssButtonValue("v3a");
    if (av != null && ac != null && pr != null && ui != null && s != null && c != null && i != null && a != null) {
        return "(AV:"+av+"/AC:"+ac+"/PR:"+pr+"/UI:"+ui+"/S:"+s+"/C:"+c+"/I:"+i+"/A:"+a+")";
    }
    return null;
}

/**
 * Retrieves the value of the CVSSv2 buttons and (if complete) performs a calculation.
 */
function processCvssV2Calculation() {
    let vector = generateCvssV2Vector();
    if (vector != null) {
        $rest.getCvssScores(vector, function(score) {
            updateGauge("#cvssv2BaseScore", score.baseScore);
            updateGauge("#cvssv2ImpactScore", score.impactSubScore);
            updateGauge("#cvssv2ExploitScore", score.exploitabilitySubScore);
        });
    }
}

/**
 * Retrieves the value of the CVSSv3 buttons and (if complete) performs a calculation.
 */
function processCvssV3Calculation() {
    let vector = generateCvssV3Vector();
    if (vector != null) {
        $rest.getCvssScores(vector, function(score) {
            updateGauge("#cvssv3BaseScore", score.baseScore);
            updateGauge("#cvssv3ImpactScore", score.impactSubScore);
            updateGauge("#cvssv3ExploitScore", score.exploitabilitySubScore);
        });
    }
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready.
 */
$(document).ready(function () {
    $rest.getPortfolioCurrentMetrics(function(metrics) {
        updateStats(metrics);
    });
    $rest.getCwes(populateCweData);


    // Listen for if the button to create a vulnerability is clicked
    $("#vulnerabilityCreateButton").on("click", function() {
        const vulnId = $common.valueWithDefault($("#vulnerabilityVulnIdInput").val(), null);
        const title = $common.valueWithDefault($("#vulnerabilityTitleInput").val(), null);
        const subTitle = $common.valueWithDefault($("#vulnerabilitySubtitleInput").val(), null);
        const description = $common.valueWithDefault($("#vulnerabilityDescriptionInput").val(), null);
        const recommendation = $common.valueWithDefault($("#vulnerabilityRecommendationInput").val(), null);
        const references = $common.valueWithDefault($("#vulnerabilityReferencesInput").val(), null);
        const credits = $common.valueWithDefault($("#vulnerabilityCreditsInput").val(), null);

        const created = $common.valueWithDefault($("#vulnerabilityCreatedInput").val(), null);
        const published = $common.valueWithDefault($("#vulnerabilityPublishedInput").val(), null);
        const updated =$common.valueWithDefault($("#vulnerabilityUpdatedInput").val(), null);

        const cweId = $common.valueWithDefault($("#vulnerabilityCweSelect").val(), null);
        const cvssV2Vector = generateCvssV2Vector();
        const cvssV3Vector = generateCvssV3Vector();
        const vulnerableVersions = $common.valueWithDefault($("#vulnerabilityVulnerableVersionsInput").val(), null);
        const patchedVersions = $common.valueWithDefault($("#vulnerabilityPatchedVersionsInput").val(), null);

        $rest.createVulnerability(vulnId, title, subTitle, description, recommendation, references, credits,
            created, published, updated, cweId, cvssV2Vector, cvssV3Vector, vulnerableVersions, patchedVersions,
            vulnerabilityCreated);
        clearInputFields();
    });


    // Style button groups used in CVSS calculators so that only one button per group is active/primary at a time.
    $(".btn-group > .btn").click(function() {
        $(this).parent().siblings().each(function() {
            $(this).children().each(function() {
                $(this).removeClass("btn-primary active");
            });
        });
        $(this).addClass("btn-primary active");

        // Check to see what calculator is being used and determine if all inputs have been selected
        if ($(this).hasClass("cvssv2-calc")) {
            processCvssV2Calculation(); // A button on the CVSSv2 calculator was pushed. Process buttons.
        } else if ($(this).hasClass("cvssv3-calc")) {
            processCvssV3Calculation(); // A button on the CVSSv3 calculator was pushed. Process buttons.
        }
    });


    // When modal closes, clear out the input fields
    $("#modalCreateVulnerability").on("hidden.bs.modal", function() {
        clearInputFields();
    });

    // Initialize and create the charts
    $(".chart").easyPieChart({
        barColor: "#3D598B",
        trackColor: "#f2f2f2",
        scaleColor: "#dfe0e0",
        scaleLength: 5,
        lineCap: "butt",
        lineWidth: 5,
        size: 90,
    });

    // Bind date range picker to all inputs named 'date'
    $('input[name="date"]').daterangepicker({
        "singleDatePicker": true,
        "showDropdowns": true,
        "linkedCalendars": false,
        "autoUpdateInput": true,
        "locale": {
            "format": "YYYY-MM-DD",
            "separator": " - "
        }
    }, function(start, end, label) {

   });

});