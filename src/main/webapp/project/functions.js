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
    let projectUuid = $.getUrlVar("uuid");
    let dependenciesTable = $("#dependenciesTable");
    for (let i=0; i<res.length; i++) {

        if (res[i].component.hasOwnProperty("purl") && res[i].component.hasOwnProperty("version")) {
            $rest.getLatestFromRepository(res[i].component.purl, updateDependencyRowWithLatest(i, res[i]));
        }

        let componenturl = "../component/?uuid=" + res[i].component.uuid;
        res[i].componenthref = "<a href=\"" + componenturl + "\">" + filterXSS(res[i].component.name)+ "</a>";
        res[i].component.version = filterXSS(res[i].component.version);
        res[i].component.group = filterXSS(res[i].component.group);

        if (res[i].component.hasOwnProperty("resolvedLicense")) {
            let licenseurl = "../license/?licenseId=" + res[i].component.resolvedLicense.licenseId;
            res[i].component.license = "<a href=\"" + licenseurl + "\">" + filterXSS(res[i].component.resolvedLicense.licenseId) + "</a>";
        }

        $rest.getDependencyCurrentMetrics(projectUuid, res[i].component.uuid, function (data) {
            res[i].component.vulnerabilities = $common.generateSeverityProgressBar(data.critical, data.high, data.medium, data.low);
            dependenciesTable.bootstrapTable("updateRow", {
                index: i,
                row: res[i].component
            });
        });
    }
    return res;
}

function updateDependencyRowWithLatest(rowNumber, rowData) {
    return function (data) {
        const dependenciesTable = $("#dependenciesTable");
        if (data.hasOwnProperty("latestVersion")) {
            if (data.latestVersion !== rowData.component.version) {
                rowData.component.version = '<span style="float:right" data-toggle="tooltip" data-placement="bottom" title="Risk: Outdated component. Current version is: '+ filterXSS(data.latestVersion) + '"><i class="fa fa-exclamation-triangle status-warning" aria-hidden="true"></i></span> ' + filterXSS(rowData.component.version);
            } else {
                rowData.component.version = '<span style="float:right" data-toggle="tooltip" data-placement="bottom" title="Component version is the latest available from the configured repositories"><i class="fa fa-exclamation-triangle status-passed" aria-hidden="true"></i></span> ' + filterXSS(rowData.component.version);
            }
            rowData.latestVersion = filterXSS(data.latestVersion);
        }
        dependenciesTable.bootstrapTable("updateRow", {index: rowNumber, row: rowData});
    };
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

        if (res[i].hasOwnProperty("cweId") && res[i].hasOwnProperty("cweName")) {
            res[i].cwefield = "<div class='truncate-ellipsis'><span>CWE-" + res[i].cweId + " " + res[i].cweName + "</span></div>";
        }

        if (res[i].hasOwnProperty("severity")) {
            res[i].severityLabel = $common.formatSeverityLabel(res[i].severity);
        }

        if (res[i].hasOwnProperty("isSuppressed") && res[i].isSuppressed === true) {
            res[i].isSuppressedLabel = '<i class="fa fa-check-square-o" aria-hidden="true"></i>';
        } else {
            res[i].isSuppressedLabel = '';
        }
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
        <div class="form-group" style="display:none" id="group-title-${row.componentUuid}-${row.vulnUuid}">
            <label for="title-${row.componentUuid}-${row.vulnUuid}">Title</label>
            <input type="text" class="form-control" disabled="disabled" id="title-${row.componentUuid}-${row.vulnUuid}" value="" data-component-uuid="${row.componentUuid}" data-vuln-uuid="${row.vulnUuid}">
        </div>
        <div class="form-group" style="display:none" id="group-subtitle-${row.componentUuid}-${row.vulnUuid}">
            <label for="subtitle-${row.componentUuid}-${row.vulnUuid}">Subtitle</label>
            <input type="text" class="form-control" disabled="disabled" id="subtitle-${row.componentUuid}-${row.vulnUuid}" value="" data-component-uuid="${row.componentUuid}" data-vuln-uuid="${row.vulnUuid}">
        </div>
        <div class="form-group" style="display:none" id="group-description-${row.componentUuid}-${row.vulnUuid}">
            <label for="description-${row.componentUuid}-${row.vulnUuid}">Description</label>
            <textarea class="form-control" disabled="disabled" rows="7" id="description-${row.componentUuid}-${row.vulnUuid}" data-component-uuid="${row.componentUuid}" data-vuln-uuid="${row.vulnUuid}"></textarea>
        </div>
        <div class="form-group" style="display:none" id="group-recommendation-${row.componentUuid}-${row.vulnUuid}">
            <label for="recommendation-${row.componentUuid}-${row.vulnUuid}">Recommendation</label>
            <textarea class="form-control" disabled="disabled" rows="7" id="recommendation-${row.componentUuid}-${row.vulnUuid}" data-component-uuid="${row.componentUuid}" data-vuln-uuid="${row.vulnUuid}"></textarea>
        </div>
        <div class="form-group" style="display:none" id="group-cvssV2Vector-${row.componentUuid}-${row.vulnUuid}">
            <label for="cvssV2Vector-${row.componentUuid}-${row.vulnUuid}">CVSSv2 Vector</label>
            <input type="text" class="form-control" disabled="disabled" id="cvssV2Vector-${row.componentUuid}-${row.vulnUuid}" value="" data-component-uuid="${row.componentUuid}" data-vuln-uuid="${row.vulnUuid}">
        </div>
        <div class="form-group" style="display:none" id="group-cvssV3Vector-${row.componentUuid}-${row.vulnUuid}">
            <label for="cvssV3Vector-${row.componentUuid}-${row.vulnUuid}">CVSSv3 Vector</label>
            <input type="text" class="form-control" disabled="disabled" id="cvssV3Vector-${row.componentUuid}-${row.vulnUuid}" value="" data-component-uuid="${row.componentUuid}" data-vuln-uuid="${row.vulnUuid}">
        </div>
    </div>
    <div class="col-sm-6 col-md-6">
        <div class="form-group">
            <label for="audit-trail-${projectUuid}-${row.componentUuid}-${row.vulnUuid}">Audit Trail</label>
            <textarea class="form-control" disabled="disabled" rows="7" id="audit-trail-${projectUuid}-${row.componentUuid}-${row.vulnUuid}" data-component-uuid="${row.componentUuid}" data-vuln-uuid="${row.vulnUuid}"></textarea>
        </div>
        <div class="form-group">
            <label for="comment-${projectUuid}-${row.componentUuid}-${row.vulnUuid}">Comment</label>
            <textarea class="form-control" rows="3" id="comment-${projectUuid}-${row.componentUuid}-${row.vulnUuid}" data-component-uuid="${row.componentUuid}" data-vuln-uuid="${row.vulnUuid}"></textarea>
            <div class="pull-right">
                <button id="addCommentButton-${projectUuid}-${row.componentUuid}-${row.vulnUuid}" class="btn btn-xs btn-warning"><span class="fa fa-comment-o"></span> Add Comment</button>
            </div>
        </div>     
        <div class="col-xs-6 input-group">
            <label for="analysis-${projectUuid}-${row.componentUuid}-${row.vulnUuid}">Analysis</label>
            <select class="form-control" style="background-color:#ffffff" id="analysis-${projectUuid}-${row.componentUuid}-${row.vulnUuid}">
                <option value="NOT_SET"></option>
                <option value="EXPLOITABLE">Exploitable</option>
                <option value="IN_TRIAGE">In Triage</option>
                <option value="FALSE_POSITIVE">False Positive</option>
                <option value="NOT_AFFECTED">Not Affected</option>
            </select>
            <span class="input-group-btn" style="vertical-align:bottom; padding-left:20px">
                <input id="suppressButton-${projectUuid}-${row.componentUuid}-${row.vulnUuid}" type="checkbox" data-toggle="toggle" data-on="<i class='fa fa-eye-slash'></i> Suppressed" data-off="<i class='fa fa-eye'></i> Suppress">
            </span>
        </div>
    </form>
    </div>
    <script type="text/javascript">
       initializeSuppressButton("#suppressButton-${projectUuid}-${row.componentUuid}-${row.vulnUuid}", ${row.isSuppressed});
       $("#suppressButton-${projectUuid}-${row.componentUuid}-${row.vulnUuid}").on("change", function() {
           let isSuppressed = $("#suppressButton-${projectUuid}-${row.componentUuid}-${row.vulnUuid}").is(':checked');
           let analysis = $("#analysis-${projectUuid}-${row.componentUuid}-${row.vulnUuid}").val();
           $rest.makeAnalysis("${projectUuid}", "${row.componentUuid}", "${row.vulnUuid}", analysis, null, isSuppressed, function() {
               updateAnalysisPanel("${projectUuid}", "${row.componentUuid}", "${row.vulnUuid}");
               $rest.refreshDependencyMetrics("${projectUuid}", "${row.componentUuid}");
           });
       });
       
       $("#analysis-${projectUuid}-${row.componentUuid}-${row.vulnUuid}").on("change", function() {
           $rest.makeAnalysis("${projectUuid}", "${row.componentUuid}", "${row.vulnUuid}", this.value, null, null, function() {
               updateAnalysisPanel("${projectUuid}", "${row.componentUuid}", "${row.vulnUuid}");
           });
       });
       $("#addCommentButton-${projectUuid}-${row.componentUuid}-${row.vulnUuid}").on("click", function() {
           let analysis = $("#analysis-${projectUuid}-${row.componentUuid}-${row.vulnUuid}").val();
           let comment = $("#comment-${projectUuid}-${row.componentUuid}-${row.vulnUuid}").val();
           $rest.makeAnalysis("${projectUuid}", "${row.componentUuid}", "${row.vulnUuid}", analysis, comment, null, function() {
               updateAnalysisPanel("${projectUuid}", "${row.componentUuid}", "${row.vulnUuid}");
           });
       });
    </script>
`;
    html.push(template);

    $rest.getVulnerabilityByUuid(row.vulnUuid, function(vuln) {
        if (vuln.hasOwnProperty("title")) {
            $("#group-title-" + row.componentUuid + "-" + row.vulnUuid).css("display", "block");
            $("#title-" + row.componentUuid + "-" + row.vulnUuid).val(filterXSS(vuln.title));
        }
        if (vuln.hasOwnProperty("subTitle")) {
            $("#group-subTitle-" + row.componentUuid + "-" + row.vulnUuid).css("display", "block");
            $("#subTitle-" + row.componentUuid + "-" + row.vulnUuid).val(filterXSS(vuln.subTitle));
        }
        if (vuln.hasOwnProperty("description")) {
            $("#group-description-" + row.componentUuid + "-" + row.vulnUuid).css("display", "block");
            $("#description-" + row.componentUuid + "-" + row.vulnUuid).val(vuln.description);
        }
        if (vuln.hasOwnProperty("recommendation")) {
            $("#group-recommendation-" + row.componentUuid + "-" + row.vulnUuid).css("display", "block");
            $("#recommendation-" + row.componentUuid + "-" + row.vulnUuid).val(vuln.recommendation);
        }
        if (vuln.hasOwnProperty("cvssV2Vector")) {
            $("#group-cvssV2Vector-" + row.componentUuid + "-" + row.vulnUuid).css("display", "block");
            $("#cvssV2Vector-" + row.componentUuid + "-" + row.vulnUuid).val(filterXSS(vuln.cvssV2Vector));
        }
        if (vuln.hasOwnProperty("cvssV3Vector")) {
            $("#group-cvssV3Vector-" + row.componentUuid + "-" + row.vulnUuid).css("display", "block");
            $("#cvssV3Vector-" + row.componentUuid + "-" + row.vulnUuid).val(filterXSS(vuln.cvssV3Vector));
        }
    });

    updateAnalysisPanel(projectUuid, row.componentUuid, row.vulnUuid);
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
    if (metric.hasOwnProperty("lastOccurrence")) {
        $("#statLastMeasurement").html(filterXSS($common.formatTimestamp(metric.lastOccurrence, true)));
    }
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

    const findingsTable = $("#findingsTable");
    findingsTable.on("click-row.bs.table", function(e, row, $tr) {
        if ($tr.next().is("tr.detail-view")) {
            findingsTable.bootstrapTable("collapseRow", $tr.data("index"));
            findingsTable.expanded = false;
        } else {
            findingsTable.bootstrapTable("collapseAllRows");
            findingsTable.bootstrapTable("expandRow", $tr.data("index"));
            findingsTable.expanded = true;
            findingsTable.expandedUuid = row.uuid;
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
});