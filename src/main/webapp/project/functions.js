/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

"use strict";

/**
 * Called by bootstrap table to format the data in the dependencies table.
 */
function formatDependenciesTable(res) {
    for (let i=0; i<res.length; i++) {
        if (res[i].component.hasOwnProperty("version")) {
            if (res[i].component.hasOwnProperty("repositoryMeta") && res[i].component.repositoryMeta.hasOwnProperty("latestVersion")) {
                if (res[i].component.repositoryMeta.latestVersion !== res[i].component.version) {
                    res[i].component.version = '<span style="float:right" data-toggle="tooltip" data-placement="bottom" title="Risk: Outdated component. Current version is: '+ filterXSS(res[i].component.repositoryMeta.latestVersion) + '"><i class="fa fa-exclamation-triangle status-warning" aria-hidden="true"></i></span> ' + filterXSS(res[i].component.version);
                } else {
                    res[i].component.version = '<span style="float:right" data-toggle="tooltip" data-placement="bottom" title="Component version is the latest available from the configured repositories"><i class="fa fa-exclamation-triangle status-passed" aria-hidden="true"></i></span> ' + filterXSS(res[i].component.version);
                }
                res[i].latestVersion = filterXSS(res[i].component.repositoryMeta.latestVersion);
            } else {
                res[i].component.version = filterXSS(res[i].component.version);
            }
        }
        let componenturl = "../component/?uuid=" + res[i].component.uuid;
        res[i].componenthref = "<a href=\"" + componenturl + "\">" + filterXSS(res[i].component.name)+ "</a>";
        res[i].component.group = filterXSS(res[i].component.group);
        res[i].component.isInternal = (res[i].component.isInternal) ? "<i class=\"fa fa-check-square-o\" aria-hidden=\"true\"></i>" : "";
        if (res[i].component.hasOwnProperty("resolvedLicense")) {
            let licenseurl = "../license/?licenseId=" + res[i].component.resolvedLicense.licenseId;
            res[i].component.license = "<a href=\"" + licenseurl + "\">" + filterXSS(res[i].component.resolvedLicense.licenseId) + "</a>";
        }
        if (res[i].hasOwnProperty("metrics")) {
            res[i].vulnerabilities = $common.generateSeverityProgressBar(res[i].metrics.critical, res[i].metrics.high, res[i].metrics.medium, res[i].metrics.low, res[i].metrics.unassigned);
        }
    }
    return res;
}

function formatProjectPropertiesTable(res) {
    for (let i=0; i<res.length; i++) {
        res[i].groupName = filterXSS(res[i].groupName);
        res[i].propertyName = filterXSS(res[i].propertyName);
        res[i].propertyValue = filterXSS(res[i].propertyValue);
        res[i].propertyType = filterXSS(res[i].propertyType);
        res[i].description = filterXSS(res[i].description);
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
        let vulnurl = "../vulnerability/?source=" + filterXSS(res[i].vulnerability.source) + "&vulnId=" + filterXSS(res[i].vulnerability.vulnId);
        res[i].vulnerability.href = $common.formatSourceLabel(res[i].vulnerability.source) + " <a href=\"" + vulnurl + "\">" + filterXSS(res[i].vulnerability.vulnId) + "</a>";

        if (res[i].vulnerability.hasOwnProperty("cweId") && res[i].vulnerability.hasOwnProperty("cweName")) {
            res[i].vulnerability.cwefield = "<div class='truncate-ellipsis'><span>CWE-" + filterXSS(res[i].vulnerability.cweId) + " " + filterXSS(res[i].vulnerability.cweName) + "</span></div>";
        } else {
            res[i].vulnerability.cwefield = "";
        }

        if (res[i].vulnerability.hasOwnProperty("severity")) {
            res[i].vulnerability.severityLabel = $common.formatSeverityLabel(filterXSS(res[i].vulnerability.severity));
        }

        if (res[i].analysis.hasOwnProperty("isSuppressed") && res[i].analysis.isSuppressed === true) {
            res[i].analysis.isSuppressedLabel = '<i class="fa fa-check-square-o" aria-hidden="true"></i>';
        } else {
            res[i].analysis.isSuppressedLabel = '';
        }

        res[i].component.name = filterXSS(res[i].component.name);
        res[i].component.group = res[i].component.hasOwnProperty("group") ? filterXSS(res[i].component.group) : "";
        res[i].component.version = res[i].component.hasOwnProperty("version") ? filterXSS(res[i].component.version) : "";
        res[i].analysis.state = res[i].analysis.hasOwnProperty("state") ? filterXSS(res[i].analysis.state) : "";
    }
    return res;
}

/**
 * Function called by bootstrap table when row is clicked/touched, and
 * expanded. This function handles the dynamic creation of the expanded
 * view with simple inline templates.
 */
function findingDetailFormatter(index, row) {
    let projectUuid = $.getUrlVar("uuid");
    let html = [];
    let template = `
    <div class="col-sm-6 col-md-6">
    <form id="form-${row.uuid}">
        <div class="form-group" style="display:none" id="group-title-${row.component.uuid}-${row.vulnerability.uuid}">
            <label for="title-${row.component.uuid}-${row.vulnerability.uuid}">Title</label>
            <input type="text" class="form-control disabled" readonly="readonly" id="title-${row.component.uuid}-${row.vulnerability.uuid}" value="" data-component-uuid="${row.component.uuid}" data-vuln-uuid="${row.vulnerability.uuid}">
        </div>
        <div class="form-group" style="display:none" id="group-subtitle-${row.component.uuid}-${row.vulnerability.uuid}">
            <label for="subtitle-${row.component.uuid}-${row.vulnerability.uuid}">Subtitle</label>
            <input type="text" class="form-control disabled" readonly="readonly" id="subtitle-${row.component.uuid}-${row.vulnerability.uuid}" value="" data-component-uuid="${row.component.uuid}" data-vuln-uuid="${row.vulnerability.uuid}">
        </div>
        <div class="form-group" style="display:none" id="group-description-${row.component.uuid}-${row.vulnerability.uuid}">
            <label for="description-${row.component.uuid}-${row.vulnerability.uuid}">Description</label>
            <textarea class="form-control disabled" readonly="readonly" rows="7" id="description-${row.component.uuid}-${row.vulnerability.uuid}" data-component-uuid="${row.component.uuid}" data-vuln-uuid="${row.vulnerability.uuid}"></textarea>
        </div>
        <div class="form-group" style="display:none" id="group-recommendation-${row.component.uuid}-${row.vulnerability.uuid}">
            <label for="recommendation-${row.component.uuid}-${row.vulnerability.uuid}">Recommendation</label>
            <textarea class="form-control disabled" readonly="readonly" rows="7" id="recommendation-${row.component.uuid}-${row.vulnerability.uuid}" data-component-uuid="${row.component.uuid}" data-vuln-uuid="${row.vulnerability.uuid}"></textarea>
        </div>
        <div class="form-group" style="display:none" id="group-cvssV2Vector-${row.component.uuid}-${row.vulnerability.uuid}">
            <label for="cvssV2Vector-${row.component.uuid}-${row.vulnerability.uuid}">CVSSv2 Vector</label>
            <input type="text" class="form-control disabled" readonly="readonly" id="cvssV2Vector-${row.component.uuid}-${row.vulnerability.uuid}" value="" data-component-uuid="${row.component.uuid}" data-vuln-uuid="${row.vulnerability.uuid}">
        </div>
        <div class="form-group" style="display:none" id="group-cvssV3Vector-${row.component.uuid}-${row.vulnerability.uuid}">
            <label for="cvssV3Vector-${row.component.uuid}-${row.vulnerability.uuid}">CVSSv3 Vector</label>
            <input type="text" class="form-control disabled" readonly="readonly" id="cvssV3Vector-${row.component.uuid}-${row.vulnerability.uuid}" value="" data-component-uuid="${row.component.uuid}" data-vuln-uuid="${row.vulnerability.uuid}">
        </div>
    </div>
    <div class="col-sm-6 col-md-6">
        <div class="form-group">
            <label for="audit-trail-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}">Audit Trail</label>
            <textarea class="form-control disabled" readonly="readonly" rows="7" id="audit-trail-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}" data-component-uuid="${row.component.uuid}" data-vuln-uuid="${row.vulnerability.uuid}"></textarea>
        </div>
        <div class="form-group">
            <label for="comment-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}">Comment</label>
            <textarea class="form-control" rows="3" id="comment-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}" data-component-uuid="${row.component.uuid}" data-vuln-uuid="${row.vulnerability.uuid}"></textarea>
            <div class="pull-right">
                <button id="addCommentButton-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}" class="btn btn-xs btn-warning"><span class="fa fa-comment-o"></span> Add Comment</button>
            </div>
        </div>     
        <div class="col-xs-6 input-group">
            <label for="analysis-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}">Analysis</label>
            <select class="form-control" style="background-color:#ffffff" id="analysis-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}">
                <option value="NOT_SET"></option>
                <option value="EXPLOITABLE">Exploitable</option>
                <option value="IN_TRIAGE">In Triage</option>
                <option value="FALSE_POSITIVE">False Positive</option>
                <option value="NOT_AFFECTED">Not Affected</option>
            </select>
            <span class="input-group-btn" style="vertical-align:bottom; padding-left:20px">
                <input id="suppressButton-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}" type="checkbox" data-toggle="toggle" data-on="<i class='fa fa-eye-slash'></i> Suppressed" data-off="<i class='fa fa-eye'></i> Suppress">
            </span>
        </div>
    </form>
    </div>
    <script type="text/javascript">
       initializeSuppressButton("#suppressButton-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}", ${row.analysis.isSuppressed});
       $("#suppressButton-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}").on("change", function() {
           let isSuppressed = $("#suppressButton-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}").is(':checked');
           let analysis = $("#analysis-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}").val();
           $rest.makeAnalysis("${projectUuid}", "${row.component.uuid}", "${row.vulnerability.uuid}", analysis, null, isSuppressed, function() {
               updateAnalysisPanel("${projectUuid}", "${row.component.uuid}", "${row.vulnerability.uuid}");
               $rest.refreshDependencyMetrics("${projectUuid}", "${row.component.uuid}");
           });
       });
       
       $("#analysis-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}").on("change", function() {
           $rest.makeAnalysis("${projectUuid}", "${row.component.uuid}", "${row.vulnerability.uuid}", this.value, null, null, function() {
               updateAnalysisPanel("${projectUuid}", "${row.component.uuid}", "${row.vulnerability.uuid}");
           });
       });
       $("#addCommentButton-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}").on("click", function() {
           let analysis = $("#analysis-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}").val();
           let comment = $("#comment-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}").val();
           $rest.makeAnalysis("${projectUuid}", "${row.component.uuid}", "${row.vulnerability.uuid}", analysis, comment, null, function() {
               $("#comment-${projectUuid}-${row.component.uuid}-${row.vulnerability.uuid}").val("");
               updateAnalysisPanel("${projectUuid}", "${row.component.uuid}", "${row.vulnerability.uuid}");
           });
       });
    </script>
`;
    html.push(template);

    $rest.getVulnerabilityByUuid(row.vulnerability.uuid, function(vuln) {
        if (vuln.hasOwnProperty("title")) {
            $("#group-title-" + row.component.uuid + "-" + row.vulnerability.uuid).css("display", "block");
            $("#title-" + row.component.uuid + "-" + row.vulnerability.uuid).val(filterXSS(vuln.title));
        }
        if (vuln.hasOwnProperty("subTitle")) {
            $("#group-subTitle-" + row.component.uuid + "-" + row.vulnerability.uuid).css("display", "block");
            $("#subTitle-" + row.component.uuid + "-" + row.vulnerability.uuid).val(filterXSS(vuln.subTitle));
        }
        if (vuln.hasOwnProperty("description")) {
            $("#group-description-" + row.component.uuid + "-" + row.vulnerability.uuid).css("display", "block");
            $("#description-" + row.component.uuid + "-" + row.vulnerability.uuid).val(vuln.description);
        }
        if (vuln.hasOwnProperty("recommendation")) {
            $("#group-recommendation-" + row.component.uuid + "-" + row.vulnerability.uuid).css("display", "block");
            $("#recommendation-" + row.component.uuid + "-" + row.vulnerability.uuid).val(vuln.recommendation);
        }
        if (vuln.hasOwnProperty("cvssV2Vector")) {
            $("#group-cvssV2Vector-" + row.component.uuid + "-" + row.vulnerability.uuid).css("display", "block");
            $("#cvssV2Vector-" + row.component.uuid + "-" + row.vulnerability.uuid).val(filterXSS(vuln.cvssV2Vector));
        }
        if (vuln.hasOwnProperty("cvssV3Vector")) {
            $("#group-cvssV3Vector-" + row.component.uuid + "-" + row.vulnerability.uuid).css("display", "block");
            $("#cvssV3Vector-" + row.component.uuid + "-" + row.vulnerability.uuid).val(filterXSS(vuln.cvssV3Vector));
        }
    });

    updateAnalysisPanel(projectUuid, row.component.uuid, row.vulnerability.uuid);
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

function updateAnalysisPanel(projectUuid, componentUuid, vulnUuid) {
    $rest.getAnalysis(projectUuid, componentUuid, vulnUuid, function(analysis) {
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
                let textarea = $("#audit-trail-" + projectUuid + "-" + componentUuid + "-" + vulnUuid);
                textarea.val(filterXSS(auditTrail));
                textarea.scrollTop(textarea[0].scrollHeight);
            }
            if (analysis.hasOwnProperty("analysisState")) {
                $("#analysis-" + projectUuid + "-" + componentUuid + "-" + vulnUuid).val(analysis.analysisState);
            }
            if (analysis.hasOwnProperty("isSuppressed")) {
                let suppressButton = $("#suppressButton-" + projectUuid + "-" + componentUuid + "-" + vulnUuid);
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
    $rest.getProjectVersions(data.name, true, function (versionData) {
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
    if (data.active) {
        $("#projectActiveInput").prop("checked", "checked");

    }

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
    $("#metricUnassigned").html(filterXSS($common.valueWithDefault(metric.unassigned, "0")));
    $("#metricIrs").html(filterXSS($common.valueWithDefault(metric.inheritedRiskScore, "0")));

    $("#statTotalComponents").html(filterXSS($common.valueWithDefault(metric.components, "0")));
    $("#statVulnerableComponents").html(filterXSS($common.valueWithDefault(metric.vulnerableComponents, "0")));
    $("#statVulnerabilities").html(filterXSS($common.valueWithDefault(metric.vulnerabilities, "0")));

    let findingsTotal = $common.valueWithDefault(metric.findingsTotal, "0");
    let findingsAudited = $common.valueWithDefault(metric.findingsAudited, "0");
    $("#statFindingsAudited").html(filterXSS(findingsAudited));
    $("#statFindingsAuditedPercent").html(filterXSS($common.calcProgressPercentLabel(findingsTotal, findingsAudited)));

    $("#statSuppressed").html(filterXSS($common.valueWithDefault(metric.suppressed, "0")));
    if (metric.hasOwnProperty("lastOccurrence")) {
        $("#statLastMeasurement").html(filterXSS($common.formatTimestamp(metric.lastOccurrence, true)));
    }
}

function getTrendData() {
    let uuid = $.getUrlVar("uuid");
    d3.selectAll(".nvtooltip").remove();
    $rest.getProjectMetrics(uuid, 90, function(metrics) {
        $chart.createSeverityTrendChart(metrics, "projectchart", "Project Vulnerabilities");
        $chart.createSinglePointPercentageTrendChart(metrics, "auditchart", "Auditing Progress", "findingsTotal", "findingsAudited", "Findings Audited %");
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
    if ($auth.hasPermission($auth.PORTFOLIO_MANAGEMENT, token)) {
        const propertiesUrl = $rest.contextPath() + URL_PROJECT + "/" + uuid + "/property";
        const projectPropertiesTable = $("#projectPropertiesTable");
        projectPropertiesTable.bootstrapTable("refresh", {url: propertiesUrl, silent: true});
        projectPropertiesTable.on("editable-save.bs.table", function(e, field, row, oldValue) {
            if (row.propertyValue !== oldValue) {
                $rest.updateProjectProperty(uuid, row.groupName, row.propertyName, row.propertyValue, function() {
                    projectPropertiesTable.bootstrapTable("refresh", {silent: true});
                });
            }
        });
    }

    $rest.getProject(uuid, populateProjectData);
    $rest.getLicensesConcise(populateLicenseData);
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
            componentUuids[i] = selections[i].component.uuid;
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
        let active = $("#projectActiveInput").is(':checked');
        $rest.updateProject(uuid, name, version, description, tags, active, function() {
            $rest.getProject(uuid, populateProjectData);
        });
    });

    $("#deleteProjectButton").on("click", function () {
        $rest.deleteProject(uuid, function() {
            window.location.href = "../projects/";
        });
    });

    $("#cloneProjectButton").on("click", function () {
        let version = $("#cloneProjectVersionInput").val();
        let includeTags = $("#cloneProjectIncludeTagsInput").is(':checked');
        let includeProperties = $("#cloneProjectIncludePropertiesInput").is(':checked');
        let includeDependencies = $("#cloneProjectIncludeDependenciesInput").is(':checked');
        let includeAuditHistory = $("#cloneProjectIncludeAuditHistoryInput").is(':checked');
        $rest.cloneProject(uuid, version, includeTags, includeProperties, includeDependencies, includeAuditHistory,
            function(data) {
                toastr.options = $common.toastrOptions;
                toastr.success("The project is being created with the cloning options specified");
            },
            function(data) {
                toastr.options = $common.toastrOptions;
                toastr.warning("An unexpected error occurred while adding a new project version. Check log for details.");
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

    const findingsTable = $("#findingsTable");
    findingsTable.on("click-row.bs.table", function(e, row, $tr) {
        if ($tr.next().is("tr.detail-view")) {
            findingsTable.bootstrapTable("collapseRow", $tr.data("index"));
            findingsTable.expanded = false;
        } else {
            findingsTable.bootstrapTable("collapseAllRows");
            findingsTable.bootstrapTable("expandRow", $tr.data("index"));
            findingsTable.expanded = true;
            findingsTable.expandedUuid = row.matrix;
        }
    });

    findingsTable.on("load-success.bs.table", function(e, data) {
        if (findingsTable.expanded === true) {
            $.each(data, function(i, team) {
                if (team.uuid === findingsTable.expandedUuid) {
                    findingsTable.bootstrapTable("expandRow", i);
                }
            });
        }
    });

    const dependenciesTable = $("#dependenciesTable");
    dependenciesTable.on("post-body.bs.table", function(e, data) {
        $('[data-toggle="tooltip"]').tooltip();
    });

    $common.bootstrapInputFile("uploadBomFileInput");
    const uploadBomButton = $("#uploadBomButton");
    uploadBomButton.on("click", function() {
        let uploadBomFileInput = document.querySelector("#uploadBomFileInput");
        let data = new FormData();
        data.set("project", uuid);
        data.set('bom', uploadBomFileInput.files[0]);
        $rest.uploadBom(data,
            function(data) {
                toastr.options = $common.toastrOptions;
                toastr.success("BOM upload successful");
                toastr.info("BOM queued for processing");
            },
            function(data) {
                toastr.options = $common.toastrOptions;
                toastr.warning("An unexpected error occurred while uploading. Check server logs for details.");
            });
    });

    // Listen for if the button to create a project property is clicked
    $("#createProjectPropertyCreateButton").on("click", function() {
        let groupName = $("#createProjectPropertyGroupNameInput").val();
        let propertyName = $("#createProjectPropertyNameInput").val();
        let propertyValue = $("#createProjectPropertyValueInput").val();
        let propertyType = $("#createProjectPropertyTypeInput").val();
        let description = $("#createProjectPropertyDescriptionInput").val();
        $rest.addProjectProperty(uuid, groupName, propertyName, propertyValue, propertyType, description, function() {
            $("#projectPropertiesTable").bootstrapTable("refresh", {silent: true});
        });
    });

    // When modal closes, clear out the input fields
    $("#modalCreateProjectProperty").on("hidden.bs.modal", function() {
        $("#createProjectPropertyGroupNameInput").val("");
        $("#createProjectPropertyNameInput").val("");
        $("#createProjectPropertyValueInput").val("");
        $("#createProjectPropertyDescriptionInput").val("");
    });

    // Listen for when the button to remove a project property is clicked
    $("#deleteProjectPropertyButton").on("click", function () {
        let projectPropertiesTable = $("#projectPropertiesTable");
        let selections = projectPropertiesTable.bootstrapTable("getSelections");
        for (let i=0; i<selections.length; i++) {
            $rest.deleteProjectProperty(uuid, selections[i].groupName, selections[i].propertyName, function() {
                projectPropertiesTable.bootstrapTable("refresh", {silent: true});
            });
        }
        projectPropertiesTable.bootstrapTable("uncheckAll");
    });

});