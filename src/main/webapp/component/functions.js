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
    const vulnerabilitiesTable = $("#vulnerabilitiesTable");
    for (let i=0; i<res.length; i++) {

        if (vulnerabilitiesTable.attr("data-audit-mode") === "true") {
            let componentUuid = $.getUrlVar("uuid");
            $rest.getAnalysis(null, componentUuid, res[i].uuid, updateVulnerabilityRowWithAnalysis(i, res[i]));
        }

        let vulnurl = "../vulnerability/?source=" + res[i].source + "&vulnId=" + res[i].vulnId;
        res[i].vulnerabilityhref = $common.formatSourceLabel(res[i].source) + " <a href=\"" + vulnurl + "\">" + filterXSS(res[i].vulnId) + "</a>";

        if (res[i].hasOwnProperty("cwe")) {
            res[i].cwefield = "<div class='truncate-ellipsis'><span>CWE-" + res[i].cwe.cweId + " " + res[i].cwe.name + "</span></div>";
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

function updateVulnerabilityRowWithAnalysis(rowNumber, rowData) {
    return function (data) {
        const vulnerabilitiesTable = $("#vulnerabilitiesTable");
        if (data.hasOwnProperty("analysisState")) {
            rowData.analysisState = data.analysisState;
        }
        if (data.hasOwnProperty("isSuppressed") && data.isSuppressed === true) {
            rowData.isSuppressedLabel = '<i class="fa fa-check-square-o" aria-hidden="true"></i>';
        } else {
            rowData.isSuppressedLabel = '';
        }
        vulnerabilitiesTable.bootstrapTable("updateRow", {index: rowNumber, row: rowData});
    };
}

function formatProjectsTable(res) {
    for (let i=0; i<res.length; i++) {
        let projecturl = "../project/?uuid=" + res[i].project.uuid;
        res[i].project.projecthref = "<a href=\"" + projecturl + "\">" + filterXSS(res[i].project.name) + "</a>";
        res[i].project.version = filterXSS(res[i].project.version);
    }
    return res;
}

function populateMetrics(metric) {
    $("#metricCritical").html(filterXSS($common.valueWithDefault(metric.critical, "0")));
    $("#metricHigh").html(filterXSS($common.valueWithDefault(metric.high, "0")));
    $("#metricMedium").html(filterXSS($common.valueWithDefault(metric.medium, "0")));
    $("#metricLow").html(filterXSS($common.valueWithDefault(metric.low, "0")));
    $("#metricIrs").html(filterXSS($common.valueWithDefault(metric.inheritedRiskScore, "0")));

    $("#statVulnerabilities").html(filterXSS($common.valueWithDefault(metric.vulnerabilities, "0")));
    $("#statSuppressed").html(filterXSS($common.valueWithDefault(metric.suppressed, "0")));
    if (metric.hasOwnProperty("lastOccurrence")) {
        $("#statLastMeasurement").html(filterXSS($common.formatTimestamp(metric.lastOccurrence, true)));
    }
}

function getTrendData() {
    let uuid = $.getUrlVar("uuid");
    d3.selectAll(".nvtooltip").remove();
    $rest.getComponentMetrics(uuid, 90, function(metrics) {
        $chart.createSeverityTrendChart(metrics, "componentchart", "Component Vulnerabilities");
    });
}

/**
 * Function called by bootstrap table when row is clicked/touched, and
 * expanded. This function handles the dynamic creation of the expanded
 * view with simple inline templates.
 */
function vulnerabilitiesDetailFormatter(index, row) {
    let componentUuid = $.getUrlVar("uuid");
    let vulnUuid = row.uuid;
    let html = [];
    let template = `
    <div class="col-sm-6 col-md-6">
    <form id="form-${componentUuid}">
        <div class="form-group" style="display:none" id="group-title-${componentUuid}-${vulnUuid}">
            <label for="title-${componentUuid}-${vulnUuid}">Title</label>
            <input type="text" class="form-control" disabled="disabled" id="title-${componentUuid}-${vulnUuid}" value="" data-component-uuid="${componentUuid}" data-vuln-uuid="${vulnUuid}">
        </div>
        <div class="form-group" style="display:none" id="group-subtitle-${componentUuid}-${vulnUuid}">
            <label for="subtitle-${componentUuid}-${vulnUuid}">Subtitle</label>
            <input type="text" class="form-control" disabled="disabled" id="subtitle-${componentUuid}-${vulnUuid}" value="" data-component-uuid="${componentUuid}" data-vuln-uuid="${vulnUuid}">
        </div>
        <div class="form-group" style="display:none" id="group-description-${componentUuid}-${vulnUuid}">
            <label for="description-${componentUuid}-${vulnUuid}">Description</label>
            <textarea class="form-control" disabled="disabled" rows="7" id="description-${componentUuid}-${vulnUuid}" data-component-uuid="${componentUuid}" data-vuln-uuid="${vulnUuid}"></textarea>
        </div>
        <div class="form-group" style="display:none" id="group-recommendation-${componentUuid}-${vulnUuid}">
            <label for="recommendation-${componentUuid}-${vulnUuid}">Recommendation</label>
            <textarea class="form-control" disabled="disabled" rows="7" id="recommendation-${componentUuid}-${vulnUuid}" data-component-uuid="${componentUuid}" data-vuln-uuid="${vulnUuid}"></textarea>
        </div>
        <div class="form-group" style="display:none" id="group-cvssV2Vector-${componentUuid}-${vulnUuid}">
            <label for="cvssV2Vector-${componentUuid}-${vulnUuid}">CVSSv2 Vector</label>
            <input type="text" class="form-control" disabled="disabled" id="cvssV2Vector-${componentUuid}-${vulnUuid}" value="" data-component-uuid="${componentUuid}" data-vuln-uuid="${vulnUuid}">
        </div>
        <div class="form-group" style="display:none" id="group-cvssV3Vector-${componentUuid}-${vulnUuid}">
            <label for="cvssV3Vector-${componentUuid}-${vulnUuid}">CVSSv3 Vector</label>
            <input type="text" class="form-control" disabled="disabled" id="cvssV3Vector-${componentUuid}-${vulnUuid}" value="" data-component-uuid="${componentUuid}" data-vuln-uuid="${vulnUuid}">
        </div>
    </div>
    <div class="col-sm-6 col-md-6">
        <div class="form-group">
            <label for="audit-trail-${componentUuid}-${vulnUuid}">Audit Trail</label>
            <textarea class="form-control" disabled="disabled" rows="7" id="audit-trail-${componentUuid}-${vulnUuid}" data-component-uuid="${componentUuid}" data-vuln-uuid="${vulnUuid}"></textarea>
        </div>
        <div class="form-group">
            <label for="comment-${componentUuid}-${vulnUuid}">Comment</label>
            <textarea class="form-control" rows="3" id="comment-${componentUuid}-${vulnUuid}" data-component-uuid="${componentUuid}" data-vuln-uuid="${vulnUuid}"></textarea>
            <div class="pull-right">
                <button id="addCommentButton-${componentUuid}-${vulnUuid}" class="btn btn-xs btn-warning"><span class="fa fa-comment-o"></span> Add Comment</button>
            </div>
        </div>     
        <div class="col-xs-6 input-group">
            <label for="analysis-${componentUuid}-${vulnUuid}">Analysis</label>
            <select class="form-control" style="background-color:#ffffff" id="analysis-${componentUuid}-${vulnUuid}">
                <option value="NOT_SET"></option>
                <option value="EXPLOITABLE">Exploitable</option>
                <option value="IN_TRIAGE">In Triage</option>
                <option value="FALSE_POSITIVE">False Positive</option>
                <option value="NOT_AFFECTED">Not Affected</option>
            </select>
            <span class="input-group-btn" style="vertical-align:bottom; padding-left:20px">
                <input id="suppressButton-${componentUuid}-${vulnUuid}" type="checkbox" data-toggle="toggle" data-on="<i class='fa fa-eye-slash'></i> Suppressed" data-off="<i class='fa fa-eye'></i> Suppress">
            </span>
        </div>
    </form>
    </div>
    <script type="text/javascript">
       initializeSuppressButton("#suppressButton-${componentUuid}-${vulnUuid}", ${row.isSuppressed});
       $("#suppressButton-${componentUuid}-${vulnUuid}").on("change", function() {
           let isSuppressed = $("#suppressButton-${componentUuid}-${vulnUuid}").is(':checked');
           let analysis = $("#analysis-${componentUuid}-${vulnUuid}").val();
           $rest.makeAnalysis(null, "${componentUuid}", "${vulnUuid}", analysis, null, isSuppressed, function() {
               updateAnalysisPanel("${componentUuid}", "${vulnUuid}");
               $rest.refreshComponentMetrics("${componentUuid}");
           });
       });
       
       $("#analysis-${componentUuid}-${vulnUuid}").on("change", function() {
           $rest.makeAnalysis(null, "${componentUuid}", "${vulnUuid}", this.value, null, null, function() {
               updateAnalysisPanel("${componentUuid}", "${vulnUuid}");
           });
       });
       $("#addCommentButton-${componentUuid}-${vulnUuid}").on("click", function() {
           let analysis = $("#analysis-${componentUuid}-${vulnUuid}").val();
           let comment = $("#comment-${componentUuid}-${vulnUuid}").val();
           $rest.makeAnalysis(null, "${componentUuid}", "${vulnUuid}", analysis, comment, null, function() {
               updateAnalysisPanel("${componentUuid}", "${vulnUuid}");
           });
       });
    </script>
`;
    html.push(template);

    $rest.getVulnerabilityByUuid(vulnUuid, function(vuln) {
        if (vuln.hasOwnProperty("title")) {
            $("#group-title-" + componentUuid + "-" + vulnUuid).css("display", "block");
            $("#title-" + componentUuid + "-" + vulnUuid).val(filterXSS(vuln.title));
        }
        if (vuln.hasOwnProperty("subTitle")) {
            $("#group-subTitle-" + componentUuid + "-" + vulnUuid).css("display", "block");
            $("#subTitle-" + componentUuid + "-" + vulnUuid).val(filterXSS(vuln.subTitle));
        }
        if (vuln.hasOwnProperty("description")) {
            $("#group-description-" + componentUuid + "-" + vulnUuid).css("display", "block");
            $("#description-" + componentUuid + "-" + vulnUuid).val(vuln.description);
        }
        if (vuln.hasOwnProperty("recommendation")) {
            $("#group-recommendation-" + componentUuid + "-" + vulnUuid).css("display", "block");
            $("#recommendation-" + componentUuid + "-" + vulnUuid).val(vuln.recommendation);
        }
        if (vuln.hasOwnProperty("cvssV2Vector")) {
            $("#group-cvssV2Vector-" + componentUuid + "-" + vulnUuid).css("display", "block");
            $("#cvssV2Vector-" + componentUuid + "-" + vulnUuid).val(filterXSS(vuln.cvssV2Vector));
        }
        if (vuln.hasOwnProperty("cvssV3Vector")) {
            $("#group-cvssV3Vector-" + componentUuid + "-" + vulnUuid).css("display", "block");
            $("#cvssV3Vector-" + componentUuid + "-" + vulnUuid).val(filterXSS(vuln.cvssV3Vector));
        }
    });

    updateAnalysisPanel(componentUuid, vulnUuid);
    return html.join("");
}

function initializeSuppressButton(selector, defaultValue) {
    let suppressButton = $(selector);
    if (defaultValue === true) {
        suppressButton.bootstrapToggle("on");
    } else {
        suppressButton.bootstrapToggle("off");
    }
}

function updateAnalysisPanel(componentUuid, vulnUuid) {
    $rest.getAnalysis(null, componentUuid, vulnUuid, function(analysis) {
        if (analysis) {
            if (analysis.hasOwnProperty("analysisComments")) {
                let auditTrail = "";
                for (let i = 0; i < analysis.analysisComments.length; i++) {
                    if (analysis.analysisComments[i].hasOwnProperty("commenter")) {
                        auditTrail += analysis.analysisComments[i].commenter + " - ";
                    }
                    auditTrail += $common.formatTimestamp(analysis.analysisComments[i].timestamp, true);
                    auditTrail += "\n";
                    auditTrail += analysis.analysisComments[i].comment;
                    auditTrail += "\n\n";
                }
                let textarea = $("#audit-trail-" + componentUuid + "-" + vulnUuid);
                textarea.val(filterXSS(auditTrail));
                textarea.scrollTop(textarea[0].scrollHeight);
            }
            if (analysis.hasOwnProperty("analysisState")) {
                $("#analysis-" + componentUuid + "-" + vulnUuid).val(analysis.analysisState);
            }
            if (analysis.hasOwnProperty("isSuppressed")) {
                let suppressButton = $("#suppressButton-" + componentUuid + "-" + vulnUuid);
                let isSuppressed = suppressButton.is(':checked');
                if (isSuppressed !== analysis.isSuppressed) {
                    if (analysis.isSuppressed) {
                        suppressButton.bootstrapToggle("on")
                    } else {
                        suppressButton.bootstrapToggle("off")
                    }
                }
            }
        }
    });
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

    // Restrict characters that can be typed into hash inputs
    $(".hash-input").keypress( function(e) {
        return ("acbdefABCDEF0123456789").indexOf(String.fromCharCode(e.which)) >= 0;
    });

    getTrendData();

    // Listen for refresh icon to be triggered
    $("#refresh").on("click", function() {
        $rest.refreshComponentMetrics(uuid, function() {
            $("#statLastMeasurement").html("Refresh triggered");
            $common.displayInfoModal("A refresh has been requested. The amount of time required to refresh is dependant on the amount of background processing currently being performed and the size of the data-set being refreshed.")
        });
    });

    const vulnerabilitiesTable = $("#vulnerabilitiesTable");
    vulnerabilitiesTable.on("click-row.bs.table", function(e, row, $tr) {
        if (vulnerabilitiesTable.attr("data-audit-mode") === "false") { // the string value of false
            vulnerabilitiesTable.bootstrapTable("collapseAllRows");
            vulnerabilitiesTable.expanded = false;
            return;
        }
        if ($tr.next().is("tr.detail-view")) {
            vulnerabilitiesTable.bootstrapTable("collapseRow", $tr.data("index"));
            vulnerabilitiesTable.expanded = false;
        } else {
            vulnerabilitiesTable.bootstrapTable("collapseAllRows");
            vulnerabilitiesTable.bootstrapTable("expandRow", $tr.data("index"));
            vulnerabilitiesTable.expanded = true;
            vulnerabilitiesTable.expandedUuid = row.uuid;
        }
    });

    vulnerabilitiesTable.on("load-success.bs.table", function(e, data) {
        if (vulnerabilitiesTable.expanded === true) {
            $.each(data, function(i, vuln) {
                if (vuln.uuid === vulnerabilitiesTable.expandedUuid) {
                    vulnerabilitiesTable.bootstrapTable("expandRow", i);
                }
            });
        }
    });

    const token = $auth.decodeToken($auth.getToken());
    if ($auth.hasPermission($auth.PORTFOLIO_MANAGEMENT, token) && $auth.hasPermission($auth.VULNERABILITY_ANALYSIS, token)) {
        // Only show the 'audit mode' button when viewing the vulnerabilities tab
        $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            let target = $(e.target).attr("href");
            if (target === "#vulnerabilitiesTab") {
                $("#globalAuditButtonContainer").css("visibility", "visible");
            } else {
                $("#globalAuditButtonContainer").css("visibility", "hidden");
            }
        });
    }

    $("#globalAuditButton").change(function() {
        vulnerabilitiesTable.attr("data-audit-mode", $(this).prop("checked"));
        if ($(this).prop("checked")) {
            vulnerabilitiesTable.bootstrapTable("showColumn", "analysisState");
            vulnerabilitiesTable.bootstrapTable("showColumn", "isSuppressedLabel");
            //vulnerabilitiesTable.bootstrapTable("refresh", {silent: true});
        } else {
            vulnerabilitiesTable.bootstrapTable("hideColumn", "analysisState");
            vulnerabilitiesTable.bootstrapTable("hideColumn", "isSuppressedLabel");
        }

        const url = $rest.contextPath() + URL_VULNERABILITY + "/component/" + uuid + "?suppressed=" + $(this).prop("checked");
        vulnerabilitiesTable.bootstrapTable("refresh", {silent: true, url: url});
    });

});