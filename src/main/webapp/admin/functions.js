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
 * Called by bootstrap table to format the data in the repository table.
 */
function formatRepositoryTable(res) {
    for (let i=0; i<res.length; i++) {
        if (res[i].enabled === true) {
            res[i].enabledLabel = '<i class="fa fa-check-square-o" aria-hidden="true"></i>';
        } else {
            res[i].enabledLabel = '';
        }
    }
    return res;
}

/**
 * Called by bootstrap table to format the data in the notification alert table.
 */
function formatNotificationAlertTable(res) {
    for (let i=0; i<res.length; i++) {
        res[i].name = filterXSS(res[i].name);
        if (res[i].hasOwnProperty("publisheer") && res[i].publisher.hasOwnProperty("name")) {
            res[i].publisher.name = filterXSS(res[i].publisher.name);
        }
    }
    return res;
}

/**
 * Called by bootstrap table to format the data in the templates table.
 */
function formatNotificationTemplateTable(res) {
    for (let i=0; i<res.length; i++) {
        if (res[i].defaultPublisher === true) {
            res[i].defaultPublisherLabel = '<i class="fa fa-check-square-o" aria-hidden="true"></i>';
        } else {
            res[i].defaultPublisherLabel = '';
        }
        res[i].name = filterXSS(res[i].name);
    }
    return res;
}

/**
 * Called by bootstrap table to format the data in the notification rule project table.
 */
function formatNotificationRuleProjectTable(res) {
    for (let i=0; i<res.length; i++) {
        res[i].name = filterXSS(res[i].name);
        res[i].version = filterXSS(res[i].version);
    }
    return res;
}

function teamData(data) {
    if (data === undefined) {
       return JSON.parse(sessionStorage["teamData"]);
    } else {
        sessionStorage["teamData"] = JSON.stringify(data);
    }
    return data;
}

/**
 * Called by bootstrap table to format the data in the team table.
 */
function formatTeamTable(res) {
    for (let i=0; i<res.length; i++) {
        if (res[i].apiKeys === undefined) {
            res[i].apiKeysNum = 0;
        } else {
            res[i].apiKeysNum = res[i].apiKeys.length;
        }

        res[i].membersNum = 0;

        if (res[i].ldapUsers !== undefined) {
            res[i].membersNum += res[i].ldapUsers.length;
        }
        if (res[i].managedUsers !== undefined) {
            res[i].membersNum += res[i].managedUsers.length;
        }
        res[i].name = filterXSS(res[i].name);
    }
    return res;
}

/**
 * Called by bootstrap table to format the data in the ldap users table.
 */
function formatLdapUserTable(res) {
    for (let i=0; i<res.length; i++) {
        if (res[i].teams === undefined) {
            res[i].teamsNum = 0;
        } else {
            res[i].teamsNum = res[i].teams.length;
        }
        res[i].username = filterXSS(res[i].username);
        res[i].dn = filterXSS(res[i].dn);
    }
    return res;
}

/**
 * Called by bootstrap table to format the data in the managed users table.
 */
function formatManagedUserTable(res) {
    for (let i=0; i<res.length; i++) {
        if (res[i].teams === undefined) {
            res[i].teamsNum = 0;
        } else {
            res[i].teamsNum = res[i].teams.length;
        }
        res[i].username = filterXSS(res[i].username);
        res[i].fullname = filterXSS(res[i].fullname);
        res[i].email = filterXSS(res[i].email);
    }
    return res;
}

/**
 * Assigns a permission by retrieving field values and calling the REST function for the service.
 */
function addProjectToRule() {
    const updateButton = $("#notificationRuleAddProjectButton");
    const ruleUuid = updateButton.attr("data-rule-uuid");
    const selections = $("#notificationRuleProjectTable").bootstrapTable("getAllSelections");
    for (let i = 0; i < selections.length; i++) {
        let projectUuid = selections[i].uuid;
        $rest.addProjectToNotificationRule(ruleUuid, projectUuid, function () {
            $("#notificationAlertTable").bootstrapTable("refresh", {silent: true});
            $("#notificationRuleProjectTable").bootstrapTable("refresh", {silent: true});
        });
    }
}

function removeProjectFromRule(ruleUuid, projectUuid) {
    $rest.removeProjectFromNotificationRule(ruleUuid, projectUuid, function () {
        $("#container-rule-" + ruleUuid + "-project-" + projectUuid).remove();
    });
}

/**
 * Function called by bootstrap table when row is clicked/touched, and
 * expanded. This function handles the dynamic creation of the expanded
 * view with simple inline templates.
 */
function notificationAlertDetailFormatter(index, row) {
    let html = [];

    let datasourceMirroringChecked = (row.notifyOn.includes("DATASOURCE_MIRRORING") ? 'checked=checked' : "");
    let filesystemChecked = (row.notifyOn.includes("FILE_SYSTEM") ? 'checked=checked' : "");
    let indexingServiceChecked = (row.notifyOn.includes("INDEXING_SERVICE") ? 'checked=checked' : "");
    let repositoryChecked = (row.notifyOn.includes("REPOSITORY") ? 'checked=checked' : "");
    let newVulnerabilityChecked = (row.notifyOn.includes("NEW_VULNERABILITY") ? 'checked=checked' : "");
    let newVulnDependencyChecked = (row.notifyOn.includes("NEW_VULNERABLE_DEPENDENCY") ? 'checked=checked' : "");
    let globalAuditChangeChecked = (row.notifyOn.includes("GLOBAL_AUDIT_CHANGE") ? 'checked=checked' : "");
    let projectAuditChangeChecked = (row.notifyOn.includes("PROJECT_AUDIT_CHANGE") ? 'checked=checked' : "");

    let levelInfoSelected = (row.notificationLevel === "INFORMATIONAL") ? 'selected=selected' : "";
    let levelWarnSelected = (row.notificationLevel === "WARNING") ? 'selected=selected' : "";
    let levelErrorSelected = (row.notificationLevel === "ERROR") ? 'selected=selected' : "";

    let destination = "";
    if (row.hasOwnProperty("publisherConfig")) {
        let publisherConfig = JSON.parse(row.publisherConfig);
        destination = publisherConfig.destination;
    }

    let destinationDisabled = "";
    let destinationEnabledCss = "required";
    if (row.publisher.publisherClass === "org.dependencytrack.notification.publisher.ConsolePublisher") {
        destinationDisabled = 'disabled="disabled"';
        destinationEnabledCss = "";
    }

    let expandNotificatiomAlertClass = "";
    let notifyOnOption;
    if (row.scope === "SYSTEM") {
        expandNotificatiomAlertClass = "hidden";
        notifyOnOption = `
            <ul class="list-group checked-list-box">
                <li class="list-group-item"><label style="font-weight:400"><input type="checkbox" ${datasourceMirroringChecked} id="updateNotificationAlertGroupDatasourceMirroringInput-${row.uuid}" data-uuid="${row.uuid}"> DATASOURCE_MIRRORING</label></li>
                <li class="list-group-item"><label style="font-weight:400"><input type="checkbox" ${filesystemChecked} id="updateNotificationAlertGroupFileSystemInput-${row.uuid}" data-uuid="${row.uuid}"> FILE_SYSTEM</label></li>
                <li class="list-group-item"><label style="font-weight:400"><input type="checkbox" ${indexingServiceChecked} id="updateNotificationAlertGroupIndexingServiceInput-${row.uuid}" data-uuid="${row.uuid}"> INDEXING_SERVICE</label></li>
                <li class="list-group-item"><label style="font-weight:400"><input type="checkbox" ${repositoryChecked} id="updateNotificationAlertGroupRepositoryInput-${row.uuid}" data-uuid="${row.uuid}"> REPOSITORY</label></li>
            </ul>
        `;
    } else if (row.scope === "PORTFOLIO") {
        notifyOnOption = `
            <ul class="list-group checked-list-box">
                <li class="list-group-item"><label style="font-weight:400"><input type="checkbox" ${newVulnerabilityChecked} id="updateNotificationAlertGroupNewVulnerabilityInput-${row.uuid}" data-uuid="${row.uuid}"> NEW_VULNERABILITY</label></li>
                <li class="list-group-item"><label style="font-weight:400"><input type="checkbox" ${newVulnDependencyChecked} id="updateNotificationAlertGroupNewVulnerableDependencyInput-${row.uuid}" data-uuid="${row.uuid}"> NEW_VULNERABLE_DEPENDENCY</label></li>
                <li class="list-group-item"><label style="font-weight:400"><input type="checkbox" ${globalAuditChangeChecked} id="updateNotificationAlertGroupGlobalAuditChangeInput-${row.uuid}" data-uuid="${row.uuid}"> GLOBAL_AUDIT_CHANGE</label></li>
                <li class="list-group-item"><label style="font-weight:400"><input type="checkbox" ${projectAuditChangeChecked} id="updateNotificationAlertGroupProjectAuditChangeInput-${row.uuid}" data-uuid="${row.uuid}"> PROJECT_AUDIT_CHANGE</label></li>
            </ul>
        `;
    }

    let limitToProjectsHtml = "";
    if (!(row.projects === undefined)) {
        for (let i = 0; i < row.projects.length; i++) {
            limitToProjectsHtml += `
            <li class="list-group-item" id="container-rule-${row.uuid}-project-${row.projects[i].uuid}">
                <a href="#" id="delete-${row.projects[i].uuid}" onclick="removeProjectFromRule('${row.uuid}', '${row.projects[i].uuid}')" data-toggle="tooltip" title="Remove Project">
                    <span class="glyphicon glyphicon-trash glyphicon-input-form pull-right"></span>
                </a>
                <span id="${row.uuid}-limit-to-project-${row.projects[i].uuid}">${row.projects[i].name} ${row.projects[i].version}</span>
            </li>`;
        }
    }
    limitToProjectsHtml += `
            <li class="list-group-item" id="container-no-limit-to-project">
                <a href="#" id="add-project-to-limit-to-${row.uuid}" data-toggle="modal" data-target="#modalNotificationRuleAddProject" data-rule="${row.uuid}" title="Add Project">
                    <span class="glyphicon glyphicon-plus-sign glyphicon-input-form pull-right"></span>
                </a>
                <span>&nbsp;</span>
            </li>`;

    let template = `
    <form id="form-${row.uuid}">
    <div class="col-md-6">
        <div class="form-group">
            <label class="required" for="updateNotificationAlertNameInput-${row.uuid}">Name</label>
            <input type="text" class="form-control required" value="${row.name}" id="updateNotificationAlertNameInput-${row.uuid}" data-uuid="${row.uuid}">
        </div>
        <div class="form-group">
            <label for="updateNotificationAlertPublisherInput-${row.uuid}">Publisher</label>
            <input type="text" class="form-control" disabled="disabled" value="${row.publisher.publisherClass}" id="updateNotificationAlertPublisherInput-${row.uuid}" data-uuid="${row.uuid}">
        </div>   
        <div class="form-group">
            <label for="updateNotificationAlertNotificationLevelInput-${row.uuid}">Notification Level</label>
            <select class="form-control" id="updateNotificationAlertNotificationLevelInput-${row.uuid}" data-uuid="${row.uuid}">
                <option value="INFORMATIONAL" ${levelInfoSelected}>INFORMATIONAL</option>
                <option value="WARNING" ${levelWarnSelected}>WARNING</option>
                <option value="ERROR" ${levelErrorSelected}>ERROR</option>
            </select>    
        </div>   
        <div class="form-group">
            <label class="${destinationEnabledCss}" for="updateNotificationAlertDestinationInput-${row.uuid}">Destination</label>
            <input type="text" class="form-control ${destinationEnabledCss}" ${destinationDisabled} value="${destination}" id="updateNotificationAlertDestinationInput-${row.uuid}" data-uuid="${row.uuid}">
        </div>  
        <div id="limitToProjectsTable-${row.uuid}" class="form-group hidden">
            <label for="limitToProjects">Limit to Projects</label>
            <ul class="list-group" id="limitToProjects">
                ${limitToProjectsHtml}
            </ul>
        </div>  
    </div>
    <div class="col-md-6">
        <div class="form-group">
            <label for="updateNotificationAlertScopeInput-${row.uuid}">Scope</label>
            <input type="text" class="form-control" disabled="disabled" value="${row.scope}" id="updateNotificationAlertScopeInput-${row.uuid}" data-uuid="${row.uuid}">
        </div>  
        <div class="form-group">
            <label for="updateNotificationAlertGroup">Notify On</label> 
            ${notifyOnOption}
        </div>
        <div style="text-align:right">
            <button type="button" class="btn btn-default ${expandNotificatiomAlertClass}" id="expandNotificatiomAlert-${row.uuid}" data-uuid="${row.uuid}"><i class="fa fa-chevron-down" id="limitToProjectsArrow-${row.uuid}" aria-hidden="true"></i> Limit To</button>
            <button type="button" class="btn btn-danger" id="deleteNotificatiomAlert-${row.uuid}" data-uuid="${row.uuid}">Delete Alert</button>
        </div>
    </div>
    </form>
    <script type="text/javascript">
        function toggleLimitProjectVisibility() {
            let table = $("#notificationAlertTable");
            let elm = $("#limitToProjectsTable-${row.uuid}");
            let arrow = $("#limitToProjectsArrow-${row.uuid}");
            if (elm.hasClass("hidden")) {
                elm.removeClass("hidden");
                arrow.removeClass("fa-chevron-down").addClass("fa-chevron-up");
                table.attr("data-project-view", "true");
            } else {
                elm.addClass("hidden");
                arrow.removeClass("fa-chevron-up").addClass("fa-chevron-down");
                table.attr("data-project-view", "false");
            }
        }
        if ("${row.scope}" === "SYSTEM") {
            $("#" + $.escapeSelector("updateNotificationAlertGroupDatasourceMirroringInput-${row.uuid}")).change($common.debounce(updateNotificationRule, 750));            
            $("#" + $.escapeSelector("updateNotificationAlertGroupFileSystemInput-${row.uuid}")).change($common.debounce(updateNotificationRule, 750));            
            $("#" + $.escapeSelector("updateNotificationAlertGroupIndexingServiceInput-${row.uuid}")).change($common.debounce(updateNotificationRule, 750));            
            $("#" + $.escapeSelector("updateNotificationAlertGroupRepositoryInput-${row.uuid}")).change($common.debounce(updateNotificationRule, 750));
        } else if ("${row.scope}" === "PORTFOLIO") {
            $("#" + $.escapeSelector("updateNotificationAlertGroupNewVulnerabilityInput-${row.uuid}")).change($common.debounce(updateNotificationRule, 750));            
            $("#" + $.escapeSelector("updateNotificationAlertGroupNewVulnerableDependencyInput-${row.uuid}")).change($common.debounce(updateNotificationRule, 750));            
            $("#" + $.escapeSelector("updateNotificationAlertGroupGlobalAuditChangeInput-${row.uuid}")).change($common.debounce(updateNotificationRule, 750));            
            $("#" + $.escapeSelector("updateNotificationAlertGroupProjectAuditChangeInput-${row.uuid}")).change($common.debounce(updateNotificationRule, 750));                        
        }
        $("#" + $.escapeSelector("updateNotificationAlertNameInput-${row.uuid}")).keydown($common.debounce(updateNotificationRule, 750));
        $("#" + $.escapeSelector("updateNotificationAlertNotificationLevelInput-${row.uuid}")).change($common.debounce(updateNotificationRule, 750));
        $("#" + $.escapeSelector("updateNotificationAlertDestinationInput-${row.uuid}")).keydown($common.debounce(updateNotificationRule, 750));
        $("#" + $.escapeSelector("expandNotificatiomAlert-${row.uuid}")).on("click", toggleLimitProjectVisibility);
        $("#" + $.escapeSelector("deleteNotificatiomAlert-${row.uuid}")).on("click", deleteNotificationRule);
        $("#" + $.escapeSelector("add-project-to-limit-to-${row.uuid}")).on("click", function () {
            $("#notificationRuleAddProjectButton").attr("data-rule-uuid", "${row.uuid}"); // Assign the uuid of the rule to the data-rule-uuid attribute of the 'Update' button
        });
    </script>
`;
    html.push(template);
    return html.join("");
}

/**
 * Creates a notification alert by retrieving field values and calling the REST function for the service.
 */
function createNotificationRule() {
    let nameField = $("#createNotificationAlertNameInput");
    let name = nameField.val();
    let scope = $("#createNotificationAlertScopeInput").val();
    let level = $("#createNotificationAlertNotificationLevelInput").val();
    let publisher = $("#createNotificationAlertPublisherInput").val();
    $rest.createNotificationRule(name, scope, level, publisher, function() {
        $("#notificationAlertTable").bootstrapTable("refresh", {silent: true});
    });
    nameField.val("");
}

/**
 * Updates a managed user by retrieving field values and calling the REST function for the service.
 */
function updateNotificationRule() {
    let uuid                = $(this).data("uuid");
    let name                = $("#" + $.escapeSelector("updateNotificationAlertNameInput-" + uuid)).val();
    let level               = $("#" + $.escapeSelector("updateNotificationAlertNotificationLevelInput-" + uuid)).val();
    let destination         = $("#" + $.escapeSelector("updateNotificationAlertDestinationInput-" + uuid)).val();

    let datasourceMirroring = $("#" + $.escapeSelector("updateNotificationAlertGroupDatasourceMirroringInput-" + uuid)).is(':checked');
    let filesystem          = $("#" + $.escapeSelector("updateNotificationAlertGroupFileSystemInput-" + uuid)).is(':checked');
    let indexingService     = $("#" + $.escapeSelector("updateNotificationAlertGroupIndexingServiceInput-" + uuid)).is(':checked');
    let repository          = $("#" + $.escapeSelector("updateNotificationAlertGroupRepositoryInput-" + uuid)).is(':checked');
    let newVulnerability    = $("#" + $.escapeSelector("updateNotificationAlertGroupNewVulnerabilityInput-" + uuid)).is(':checked');
    let newVulnDependency   = $("#" + $.escapeSelector("updateNotificationAlertGroupNewVulnerableDependencyInput-" + uuid)).is(':checked');
    let globalAuditChange   = $("#" + $.escapeSelector("updateNotificationAlertGroupGlobalAuditChangeInput-" + uuid)).is(':checked');
    let projectAuditChange  = $("#" + $.escapeSelector("updateNotificationAlertGroupProjectAuditChangeInput-" + uuid)).is(':checked');

    let publisherConfig = (destination != null) ? JSON.stringify({ destination: destination }) : null;
    let notifyOn = [];
    if (datasourceMirroring) { notifyOn.push("DATASOURCE_MIRRORING"); }
    if (filesystem) { notifyOn.push("FILE_SYSTEM"); }
    if (indexingService) { notifyOn.push("INDEXING_SERVICE"); }
    if (repository) { notifyOn.push("REPOSITORY"); }
    if (newVulnerability) { notifyOn.push("NEW_VULNERABILITY"); }
    if (newVulnDependency) { notifyOn.push("NEW_VULNERABLE_DEPENDENCY"); }
    if (globalAuditChange) { notifyOn.push("GLOBAL_AUDIT_CHANGE"); }
    if (projectAuditChange) { notifyOn.push("PROJECT_AUDIT_CHANGE"); }

    $rest.updateNotificationRule(uuid, name, level, publisherConfig, notifyOn, function() {
        $("#notificationAlertTable").bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Deletes a team by retrieving field values and calling the REST function for the service.
 */
function deleteNotificationRule() {
    const ruleUuid = $(this).data("uuid");
    $rest.deleteNotificationRule(ruleUuid, function() {
        let table = $('#notificationAlertTable');
        table.expanded = false;
        table.bootstrapTable("collapseAllRows");
        table.bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Function called by bootstrap table when row is clicked/touched, and
 * expanded. This function handles the dynamic creation of the expanded
 * view with simple inline templates.
 */
function notificationTemplateDetailFormatter(index, row) {
    let html = [];

    let template = `
    <form id="form-${row.uuid}">
    <div class="col-md-6">
        <div class="form-group">
            <label class="required" for="updateNotificationTemplateNameInput">Name</label>
            <input type="text" class="form-control required" disabled="disabled" value="${row.name}" id="updateNotificationTemplateNameInput-${row.uuid}">
        </div>
        <div class="form-group">
            <label class="required" for="updateNotificationTemplatePublisherClassInput">Publisher Class</label>
            <input type="email" class="form-control required" disabled="disabled" value="${row.publisherClass}" id="updateNotificationTemplatePublisherClassInput-${row.uuid}">
        </div>   
        <div class="form-group">
            <label class="required" for="updateNotificationTemplateDescriptionInput">Description</label>
            <textarea class="form-control" disabled="disabled" rows="4" id="updateNotificationTemplateDescriptionInput-${row.uuid}">${row.description}</textarea>
        </div>   
    </div>
        <div class="col-md-6">
        <div class="form-group">
            <label class="required" for="updateNotificationTemplateMimetypeInput">Template Mimetype</label>
            <input type="text" class="form-control required" disabled="disabled" value="${row.templateMimeType}" id="updateNotificationTemplateMimetypeInput-${row.uuid}">
        </div>
        <div class="form-group">
            <label class="required" for="updateNotificationTemplateTemplateInput">Template</label>
            <textarea class="form-control formattedTemplateContent" disabled="disabled" rows="10" wrap="off" id="updateNotificationTemplateTemplateInput-${row.uuid}">${row.template}</textarea>
        </div>   
    </div>
    </form>
`;
    html.push(template);
    return html.join("");
}

/**
 * Function called by bootstrap table when row is clicked/touched, and
 * expanded. This function handles the dynamic creation of the expanded
 * view with simple inline templates.
 */
function teamDetailFormatter(index, row) {
    let html = [];

    let apiKeysHtml = "";
    if (!(row.apiKeys === undefined)) {
        for (let i = 0; i < row.apiKeys.length; i++) {
            apiKeysHtml += `
            <li class="list-group-item" id="container-apikey-${row.apiKeys[i].key}">
                <a href="#" id="delete-${row.apiKeys[i].key}" onclick="deleteApiKey('${row.apiKeys[i].key}')" data-toggle="tooltip" title="Delete API Key">
                    <span class="glyphicon glyphicon-trash glyphicon-input-form pull-right"></span>
                </a>
                <a href="#" id="regen-${row.apiKeys[i].key}" onclick="regenerateApiKey('${row.apiKeys[i].key}')" data-toggle="tooltip" title="Regenerate New API Key">
                    <span class="glyphicon glyphicon-refresh glyphicon-input-form pull-right spacer-horizontal-10"></span>
                </a>
                <span id="apikey-${row.apiKeys[i].key}">${row.apiKeys[i].key}</span>
            </li>`;
        }
    }
    apiKeysHtml += `
            <li class="list-group-item" id="container-no-apikey">
                <a href="#" id="add-apikey" onclick="addApiKey('${row.uuid}')" data-toggle="tooltip" title="Add API Key">
                    <span class="glyphicon glyphicon-plus-sign glyphicon-input-form pull-right"></span>
                </a>
                <span>&nbsp;</span>
            </li>`;

    let permissionsHtml = "";
    if (!(row.permissions === undefined)) {
        for (let i = 0; i < row.permissions.length; i++) {
            permissionsHtml += `
            <li class="list-group-item" id="container-permission-${row.permissions[i].name}">
                <a href="#" id="delete-${row.permissions[i].name}" onclick="removePermissionFromTeam('${row.permissions[i].name}', '${row.uuid}')" data-toggle="tooltip" title="Remove Permission">
                    <span class="glyphicon glyphicon-trash glyphicon-input-form pull-right"></span>
                </a>
                <span id="${row.username}-permission-${row.permissions[i].name}">${row.permissions[i].name}</span>
            </li>`;
        }
    }
    permissionsHtml += `
            <li class="list-group-item" id="container-no-permission">
                <a href="#" id="add-permission-to-${row.uuid}" data-toggle="modal" data-target="#modalAssignPermission" data-uuid="${row.uuid}" title="Add Permission">
                    <span class="glyphicon glyphicon-plus-sign glyphicon-input-form pull-right"></span>
                </a>
                <span>&nbsp;</span>
            </li>`;

    let membersHtml = "";
    if (!(row.ldapUsers === undefined)) {
        for (let i = 0; i < row.ldapUsers.length; i++) {
            membersHtml += `
            <li class="list-group-item" id="container-${row.uuid}-${row.ldapUsers[i].username}-membership">
                <a href="#" onclick="removeTeamMembership('${row.uuid}', '${row.ldapUsers[i].username}')" data-toggle="tooltip" title="Remove User From Team">
                    <span class="glyphicon glyphicon-trash glyphicon-input-form pull-right"></span>
                </a>
                ${row.ldapUsers[i].username}
            </li>`;
        }
    }
    if (!(row.managedUsers === undefined)) {
        for (let i = 0; i < row.managedUsers.length; i++) {
            membersHtml += `
            <li class="list-group-item" id="container-${row.uuid}-${row.managedUsers[i].username}-membership">
                <a href="#" onclick="removeTeamMembership('${row.uuid}', '${row.managedUsers[i].username}')" data-toggle="tooltip" title="Remove User From Team">
                    <span class="glyphicon glyphicon-trash glyphicon-input-form pull-right"></span>
                </a>
                ${row.managedUsers[i].username}
            </li>`;
        }
    }

    let template = `
    <div class="col-sm-6 col-md-6">
    <form id="form-${row.uuid}">
        <div class="form-group">
            <label for="inputTeamName">Team Name</label>
            <input type="text" class="form-control" id="inputTeamName-${row.uuid}" placeholder="Name" value="${row.name}" data-team-uuid="${row.uuid}">
        </div>
        <div class="form-group">
            <label for="inputApiKeys">API Keys</label>
            <ul class="list-group" id="inputApiKeys">
                ${apiKeysHtml}
            </ul>
        </div> 
        <div class="form-group">
            <label for="inputPermissions">Permissions</label>
            <ul class="list-group" id="inputPermissions">
                ${permissionsHtml}
            </ul>
        </div> 
    </div>
    <div class="col-sm-6 col-md-6">
        <div class="form-group">
            <label for="inputTeamMembers">Team Members</label>
            <ul class="list-group" id="inputTeamMembers">
                ${membersHtml}
            </ul>
        </div>
        <button type="button" class="btn btn-danger pull-right" id="deleteTeam-${row.uuid}" data-team-uuid="${row.uuid}">Delete Team</button>
    </form>
    </div>
    <script type="text/javascript">
        $("#" + $.escapeSelector("inputTeamName-${row.uuid}")).keypress($common.debounce(updateTeam, 750));
        $("#" + $.escapeSelector("deleteTeam-${row.uuid}")).on("click", deleteTeam);
        $("#" + $.escapeSelector("add-permission-to-${row.uuid}")).on("click", function () {
            $("#assignPermission").attr("data-uuid", $(this).data("uuid")); // Assign the team to the data-uuid attribute of the 'Update' button
        });
    </script>
`;
    html.push(template);
    return html.join("");
}

/**
 * Function called by bootstrap table when row is clicked/touched, and
 * expanded. This function handles the dynamic creation of the expanded
 * view with simple inline templates.
 */
function ldapUserDetailFormatter(index, row) {
    let html = [];

    let teamsHtml = "";
    if (!(row.teams === undefined)) {
        for (let i = 0; i < row.teams.length; i++) {
            teamsHtml += `
            <li class="list-group-item" id="container-apikey-${row.teams[i].key}">
                <a href="#" id="delete-${row.teams[i].uuid}" onclick="removeTeamMembership('${row.teams[i].uuid}', '${row.username}')" data-toggle="tooltip" title="Remove from Team">
                    <span class="glyphicon glyphicon-trash glyphicon-input-form pull-right"></span>
                </a>
                <span id="${row.username}-team-${row.teams[i].uuid}">${row.teams[i].name}</span>
            </li>`;
        }
    }
    teamsHtml += `
            <li class="list-group-item" id="container-no-apikey">
                <a href="#" id="add-user-${row.username}-to-team" data-toggle="modal" data-target="#modalAssignTeamToUser" data-username="${row.username}" title="Add to Team">
                    <span class="glyphicon glyphicon-plus-sign glyphicon-input-form pull-right"></span>
                </a>
                <span>&nbsp;</span>
            </li>`;

    let permissionsHtml = "";
    if (!(row.permissions === undefined)) {
        for (let i = 0; i < row.permissions.length; i++) {
            permissionsHtml += `
            <li class="list-group-item" id="container-permission-${row.permissions[i].name}">
                <a href="#" id="delete-${row.permissions[i].name}" onclick="removePermission('${row.permissions[i].name}', '${row.username}')" data-toggle="tooltip" title="Remove Permission">
                    <span class="glyphicon glyphicon-trash glyphicon-input-form pull-right"></span>
                </a>
                <span id="${row.username}-permission-${row.permissions[i].name}">${row.permissions[i].name}</span>
            </li>`;
        }
    }
    permissionsHtml += `
            <li class="list-group-item" id="container-no-permission">
                <a href="#" id="add-permission-to-${row.username}" data-toggle="modal" data-target="#modalAssignPermission" data-username="${row.username}" title="Add Permission">
                    <span class="glyphicon glyphicon-plus-sign glyphicon-input-form pull-right"></span>
                </a>
                <span>&nbsp;</span>
            </li>`;

    let template = `
    <div class="col-sm-6 col-md-6">
    <form id="form-${row.uuid}">
        <div class="form-group">
            <label for="inputApiKeys">Team Membership</label>
            <ul class="list-group" id="inputApiKeys">
                ${teamsHtml}
            </ul>
        </div> 
        <div class="form-group">
            <label for="inputPermissions">Permissions</label>
            <ul class="list-group" id="inputPermissions">
                ${permissionsHtml}
            </ul>
        </div> 
    </div>
    <div class="col-sm-6 col-md-6">
        <!-- Perhaps other fields here in the future? -->
        <button type="button" class="btn btn-danger pull-right" id="deleteUser-${row.username}" data-user-username="${row.username}">Delete User</button>
    </form>
    </div>
    <script type="text/javascript">
        $("#" + $.escapeSelector("deleteUser-${row.username}")).on("click", deleteLdapUser);
        $("#" + $.escapeSelector("add-user-${row.username}-to-team")).on("click", function () {
            $("#assignTeamToUser").attr("data-username", $(this).data("username")); // Assign the username to the data-username attribute of the 'Update' button
        });
        $("#" + $.escapeSelector("add-permission-to-${row.username}")).on("click", function () {
            $("#assignPermission").attr("data-username", $(this).data("username")); // Assign the username to the data-username attribute of the 'Update' button
        });
    </script>
`;
    html.push(template);
    return html.join("");
}

/**
 * Function called by bootstrap table when row is clicked/touched, and
 * expanded. This function handles the dynamic creation of the expanded
 * view with simple inline templates.
 */
function managedUserDetailFormatter(index, row) {
    let html = [];

    let teamsHtml = "";
    if (!(row.teams === undefined)) {
        for (let i = 0; i < row.teams.length; i++) {
            teamsHtml += `
            <li class="list-group-item" id="container-apikey-${row.teams[i].key}">
                <a href="#" id="delete-${row.teams[i].uuid}" onclick="removeTeamMembership('${row.teams[i].uuid}', '${row.username}')" data-toggle="tooltip" title="Remove from Team">
                    <span class="glyphicon glyphicon-trash glyphicon-input-form pull-right"></span>
                </a>
                <span id="${row.username}-team-${row.teams[i].uuid}">${row.teams[i].name}</span>
            </li>`;
        }
    }
    teamsHtml += `
            <li class="list-group-item" id="container-no-apikey">
                <a href="#" id="add-user-${row.username}-to-team" data-toggle="modal" data-target="#modalAssignTeamToUser" data-username="${row.username}" title="Add to Team">
                    <span class="glyphicon glyphicon-plus-sign glyphicon-input-form pull-right"></span>
                </a>
                <span>&nbsp;</span>
            </li>`;

    let permissionsHtml = "";
    if (!(row.permissions === undefined)) {
        for (let i = 0; i < row.permissions.length; i++) {
            permissionsHtml += `
            <li class="list-group-item" id="container-permission-${row.permissions[i].name}">
                <a href="#" id="delete-${row.permissions[i].name}" onclick="removePermission('${row.permissions[i].name}', '${row.username}')" data-toggle="tooltip" title="Remove Permission">
                    <span class="glyphicon glyphicon-trash glyphicon-input-form pull-right"></span>
                </a>
                <span id="${row.username}-permission-${row.permissions[i].name}">${row.permissions[i].name}</span>
            </li>`;
        }
    }
    permissionsHtml += `
            <li class="list-group-item" id="container-no-permission">
                <a href="#" id="add-permission-to-${row.username}" data-toggle="modal" data-target="#modalAssignPermission" data-username="${row.username}" title="Add Permission">
                    <span class="glyphicon glyphicon-plus-sign glyphicon-input-form pull-right"></span>
                </a>
                <span>&nbsp;</span>
            </li>`;


    let forcePasswordChange = (row.forcePasswordChange ? 'checked=checked' : "");
    let nonExpiryPassword = (row.nonExpiryPassword ? 'checked=checked' : "");
    let suspended = (row.suspended ? 'checked=checked' : "");

    let template = `
    <div class="col-md-6">
    <form id="form-${row.uuid}">
        <div class="form-group">
            <label for="inputApiKeys">Team Membership</label>
            <ul class="list-group" id="inputApiKeys">
                ${teamsHtml}
            </ul>
        </div> 
        <div class="form-group">
            <label for="inputPermissions">Permissions</label>
            <ul class="list-group" id="inputPermissions">
                ${permissionsHtml}
            </ul>
        </div> 
    </div>
    <div class="col-md-6">
        <div class="form-group">
            <label class="required" for="updateManagedUserFullnameInput">Full Name</label>
            <input type="text" class="form-control required" value="${row.fullname}" id="updateManagedUserFullnameInput-${row.username}" data-username="${row.username}">
        </div>
        <div class="form-group">
            <label class="required" for="updateManagedUserEmailInput">Email</label>
            <input type="email" class="form-control required" value="${row.email}" id="updateManagedUserEmailInput-${row.username}" data-username="${row.username}">
        </div>              
        <div class="checkbox inDetailFormatterForm">
            <label><input type="checkbox" ${forcePasswordChange} id="updateManagedUserForcePasswordChangeInput-${row.username}" data-username="${row.username}"> User must change password at next login</label>
        </div>
        <div class="checkbox inDetailFormatterForm">
            <label><input type="checkbox" ${nonExpiryPassword} id="updateManagedUserNonExpiryPasswordInput-${row.username}" data-username="${row.username}"> Password never expires</label>
        </div>
        <div class="checkbox inDetailFormatterForm">
            <label><input type="checkbox" ${suspended} id="updateManagedUserSuspendedInput-${row.username}" data-username="${row.username}"> Suspended</label>
        </div>
        <div class="inDetailFormatterForm">
            <button type="button" class="btn btn-danger pull-right" id="deleteUser-${row.username}" data-user-username="${row.username}">Delete User</button>
        </div>
    </form>
    </div>
    <script type="text/javascript">
        $("#" + $.escapeSelector("deleteUser-${row.username}")).on("click", deleteManagedUser);
        $("#" + $.escapeSelector("add-user-${row.username}-to-team")).on("click", function () {
            $("#assignTeamToUser").attr("data-username", $(this).data("username")); // Assign the username to the data-username attribute of the 'Update' button
        });
        $("#" + $.escapeSelector("add-permission-to-${row.username}")).on("click", function () {
            $("#assignPermission").attr("data-username", $(this).data("username")); // Assign the username to the data-username attribute of the 'Update' button
        });
        $("#" + $.escapeSelector("updateManagedUserFullnameInput-${row.username}")).keydown($common.debounce(updateManagedUser, 750));
        $("#" + $.escapeSelector("updateManagedUserEmailInput-${row.username}")).keydown($common.debounce(updateManagedUser, 750));
        $("#" + $.escapeSelector("updateManagedUserForcePasswordChangeInput-${row.username}")).change($common.debounce(updateManagedUser, 750));
        $("#" + $.escapeSelector("updateManagedUserNonExpiryPasswordInput-${row.username}")).change($common.debounce(updateManagedUser, 750));
        $("#" + $.escapeSelector("updateManagedUserSuspendedInput-${row.username}")).change($common.debounce(updateManagedUser, 750));
    </script>
`;
    html.push(template);
    return html.join("");
}

/**
 * Creates a team by retrieving field values and calling the REST function for the service.
 */
function createTeam() {
    let inputField = $("#createTeamNameInput");
    let teamName = inputField.val();
    $rest.createTeam(teamName, function() {
        $("#teamsTable").bootstrapTable("refresh", {silent: true});
    });
    inputField.val("");
}

/**
 * Updates a team by retrieving field values and calling the REST function for the service.
 */
function updateTeam() {
    let teamUuid = $(this).data("team-uuid");
    let teamName = $("#inputTeamName-" + teamUuid).val();
    $rest.updateTeam(teamUuid, teamName, function() {
        $("#teamsTable").bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Deletes a team by retrieving field values and calling the REST function for the service.
 */
function deleteTeam() {
    const teamUuid = $(this).data("team-uuid");
    $rest.deleteTeam(teamUuid, function() {
        let table = $('#teamsTable');
        table.expanded = false;
        table.bootstrapTable("collapseAllRows");
        table.bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Updates a managed user by retrieving field values and calling the REST function for the service.
 */
function updateManagedUser() {
    let username    = $(this).data("username");
    let fullname    = $("#" + $.escapeSelector("updateManagedUserFullnameInput-" + username)).val();
    let email       = $("#" + $.escapeSelector("updateManagedUserEmailInput-" + username)).val();
    let forceChange = $("#" + $.escapeSelector("updateManagedUserForcePasswordChangeInput-" + username)).is(':checked');
    let nonExpiry   = $("#" + $.escapeSelector("updateManagedUserNonExpiryPasswordInput-" + username)).is(':checked');
    let suspended   = $("#" + $.escapeSelector("updateManagedUserSuspendedInput-" + username)).is(':checked');
    $rest.updateManagedUser(username, fullname, email, null, null, forceChange, nonExpiry, suspended, function() {
        $("#managedUsersTable").bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Creates a managed user by retrieving field values and calling the REST function for the service.
 */
function createManagedUser() {
    const usernameField  = $("#createManagedUserNameInput");
    const fullnameField  = $("#createManagedUserFullnameInput");
    const emailField     = $("#createManagedUserEmailInput");
    const passwordField  = $("#createManagedUserPasswordInput");
    const confirmField   = $("#createManagedUserConfirmInput");
    const forceChngField = $("#createManagedUserForcePasswordChangeInput");
    const nonExpiryField = $("#createManagedUserNonExpiryPasswordInput");
    const suspendedField = $("#createManagedUserSuspendedInput");

    const username    = usernameField.val();
    const fullname    = fullnameField.val();
    const email       = emailField.val();
    const password    = passwordField.val();
    const confirm     = confirmField.val();
    const forcechange = forceChngField.is(':checked');
    const nonexpiry   = nonExpiryField.is(':checked');
    const suspended   = suspendedField.is(':checked');

    $rest.createManagedUser(username, fullname, email, password, confirm, forcechange, nonexpiry, suspended, function() {
        $("#managedUsersTable").bootstrapTable("refresh", {silent: true});
    });

    usernameField.val("");
    fullnameField.val("");
    emailField.val("");
    passwordField.val("");
    confirmField.val("");
    forceChngField.attr('checked', false);
    nonExpiryField.attr('checked', false);
    suspendedField.attr('checked', false);
}

/**
 * Deletes a managed user by retrieving field values and calling the REST function for the service.
 */
function deleteManagedUser() {
    const username = $(this).data("user-username");
    $rest.deleteManagedUser(username, function() {
        let table = $('#managedUsersTable');
        table.expanded = false;
        table.bootstrapTable("collapseAllRows");
        table.bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Creates a LDAP user by retrieving field values and calling the REST function for the service.
 */
function createLdapUser() {
    const inputField = $("#createLdapUserNameInput");
    const username = inputField.val();
    $rest.createLdapUser(username, function() {
        $("#ldapUsersTable").bootstrapTable("refresh", {silent: true});
    });
    inputField.val("");
}

/**
 * Deletes a LDAP user by retrieving field values and calling the REST function for the service.
 */
function deleteLdapUser() {
    const username = $(this).data("user-username");
    $rest.deleteLdapUser(username, function() {
        let table = $('#ldapUsersTable');
        table.expanded = false;
        table.bootstrapTable("collapseAllRows");
        table.bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Creates a API key by retrieving field values and calling the REST function for the service.
 */
function addApiKey(uuid) {
    $rest.addApiKey(uuid, function (data) {
        $("#teamsTable").bootstrapTable("refresh", {silent: true});
    });
}


/**
 * Regenerates a API key by retrieving field values and calling the REST function for the service.
 */
function regenerateApiKey(apikey) {
    $rest.regenerateApiKey(apikey, function (data) {
        $("#apikey-" + apikey).html(filterXSS(data.key));
        $("#apikey-" + apikey).attr("id", "apikey-" + data.key);
        $("#regen-" + apikey).attr("id", "regen-" + data.key);
        $("#regen-" + data.key).attr("onclick", "regenerateApiKey('" + data.key + "')");
        $("#delete-" + apikey).attr("id", "delete-" + data.key);
        $("#delete-" + data.key).attr("onclick", "deleteApiKey('" + data.key + "')");
        $("#teamsTable").bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Deletes a API key by retrieving field values and calling the REST function for the service.
 */
function deleteApiKey(apikey) {
    $rest.deleteApiKey(apikey, function (data) {
        $("#container-apikey-" + apikey).remove();
        $("#teamsTable").bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Assigns a user to a team by retrieving field values and calling the REST function for the service.
 */
function assignTeamToUser() {
    const username = $("#assignTeamToUser").attr("data-username");
    const selections = $("#teamsMembershipTable").bootstrapTable("getAllSelections");
    for (let i = 0; i < selections.length; i++) {
        let uuid = selections[i].uuid;
        $rest.assignUserToTeam(username, uuid, function (data) {
                $("#teamsTable").bootstrapTable("refresh", {silent: true});
                $("#managedUsersTable").bootstrapTable("refresh", {silent: true});
                $("#ldapUsersTable").bootstrapTable("refresh", {silent: true});
            }
        );
    }
}

/**
 * Removes assignment of a user to a team by retrieving field values and calling the REST function for the service.
 */
function removeTeamMembership(uuid, username) {
    $rest.removeUserFromTeam(username, uuid, function (data) {
        $("#container-" + uuid + "-" + username + "-membership").remove();
        $("#teamsTable").bootstrapTable("refresh", {silent: true});
        $("#managedUsersTable").bootstrapTable("refresh", {silent: true});
        $("#ldapUsersTable").bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Assigns a permission by retrieving field values and calling the REST function for the service.
 */
function assignPermission() {
    const updateButton = $("#assignPermission");
    const username = updateButton.attr("data-username");
    const uuid = updateButton.attr("data-uuid");
    const selections = $("#permissionsTable").bootstrapTable("getAllSelections");
    if (username) {
        for (let i = 0; i < selections.length; i++) {
            let permissionName = selections[i].name;
            $rest.assignPermissionToUser(username, permissionName, function (data) {
                    $("#teamsTable").bootstrapTable("refresh", {silent: true});
                    $("#managedUsersTable").bootstrapTable("refresh", {silent: true});
                    $("#ldapUsersTable").bootstrapTable("refresh", {silent: true});
                }
            );
        }
    } else if (uuid) {
        for (let i = 0; i < selections.length; i++) {
            let permissionName = selections[i].name;
            $rest.assignPermissionToTeam(uuid, permissionName, function (data) {
                    $("#teamsTable").bootstrapTable("refresh", {silent: true});
                    $("#managedUsersTable").bootstrapTable("refresh", {silent: true});
                    $("#ldapUsersTable").bootstrapTable("refresh", {silent: true});
                }
            );
        }
    }
}

/**
 * Removes permission by retrieving field values and calling the REST function for the service.
 */
function removePermission(permissionName, username) {
    $rest.removePermissionFromUser(username, permissionName, function (data) {
        $("#teamsTable").bootstrapTable("refresh", {silent: true});
        $("#managedUsersTable").bootstrapTable("refresh", {silent: true});
        $("#ldapUsersTable").bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Removes permission by retrieving field values and calling the REST function for the service.
 */
function removePermissionFromTeam(permissionName, uuid) {
    $rest.removePermissionFromTeam(uuid, permissionName, function (data) {
        $("#teamsTable").bootstrapTable("refresh", {silent: true});
        $("#managedUsersTable").bootstrapTable("refresh", {silent: true});
        $("#ldapUsersTable").bootstrapTable("refresh", {silent: true});
    });
}

/**
 * Dynamically populates all of the config properties.
 */
function populateConfigProperties(data) {
    for (let i=0; i<data.length; i++) {
        let input = $("input[data-group-name='"+ data[i].groupName + "'][data-property-name='" + data[i].propertyName + "']");
        if ("BOOLEAN" === data[i].propertyType && "true" === data[i].propertyValue) {
            input.prop("checked", "checked");
            if (input.attr("data-toggle") === "toggle") {
                input.bootstrapToggle('on')
            }
        }
        input.val(data[i].propertyValue);
    }
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {

    // Initialize all tooltips
    $('[data-toggle="tooltip"]').tooltip();

    // Listen for if the button to create a notification alert is clicked
    $("#createNotificationAlertCreateButton").on("click", createNotificationRule);

    // Listen for if the button to add a project to a notification alert is clicked
    $("#notificationRuleAddProjectButton").on("click", addProjectToRule);

    // Listen for if the button to create a team is clicked
    $("#createTeamCreateButton").on("click", createTeam);

    // Listen for if the button to create a user is clicked
    $("#createLdapUserCreateButton").on("click", createLdapUser);

    // Listen for if the button to create a user is clicked
    $("#createManagedUserCreateButton").on("click", createManagedUser);

    // Listen for if the button to assign a team to a user is clicked
    $("#assignTeamToUser").on("click", assignTeamToUser);

    // Listen for if the button to assign a permission is clicked
    $("#assignPermission").on("click", assignPermission);

    // When modal closes, clear out the input fields
    $("#modalCreateTeam").on("hidden.bs.modal", function () {
        $("#createTeamNameInput").val("");
    });
    $("#modalCreateLdapUser").on("hidden.bs.modal", function () {
        $("#createLdapUserNameInput").val("");
    });
    $("#modalCreateManagedUser").on("hidden.bs.modal", function () {
        $("#createManagedUserNameInput").val("");
    });

    // When modal is about to be shown, update the data model
    const teamsMembershipTable = $("#teamsMembershipTable");
    $("#modalAssignTeamToUser").on("show.bs.modal", function () {
        teamsMembershipTable.bootstrapTable("load", teamData());
        teamsMembershipTable.bootstrapTable("refresh", {silent: true});
    });

    const notificationAlertTable = $("#notificationAlertTable");
    notificationAlertTable.on("click-row.bs.table", function(e, row, $tr) {
        if ($tr.next().is("tr.detail-view")) {
            notificationAlertTable.bootstrapTable("collapseRow", $tr.data("index"));
            notificationAlertTable.expanded = false;
        } else {
            notificationAlertTable.bootstrapTable("collapseAllRows");
            notificationAlertTable.bootstrapTable("expandRow", $tr.data("index"));
            notificationAlertTable.expanded = true;
            notificationAlertTable.expandedUuid = row.uuid;
        }
    });

    notificationAlertTable.on("load-success.bs.table", function(e, data) {
        if (notificationAlertTable.expanded === true) {
            $.each(data, function(i, rule) {
                if (rule.uuid === notificationAlertTable.expandedUuid) {
                    notificationAlertTable.bootstrapTable("expandRow", i);
                    let limitToExpanded = notificationAlertTable.attr("data-project-view");
                    if (limitToExpanded === "true") {
                        $("#limitToProjectsTable-" + rule.uuid).removeClass("hidden");
                        $("#limitToProjectsArrow-" + rule.uuid).removeClass("fa-chevron-down").addClass("fa-chevron-up");
                    }
                }
            });
        }
    });

    const notificationTemplateTable = $("#notificationTemplateTable");
    notificationTemplateTable.on("click-row.bs.table", function(e, row, $tr) {
        if ($tr.next().is("tr.detail-view")) {
            notificationTemplateTable.bootstrapTable("collapseRow", $tr.data("index"));
            notificationTemplateTable.expanded = false;
        } else {
            notificationTemplateTable.bootstrapTable("collapseAllRows");
            notificationTemplateTable.bootstrapTable("expandRow", $tr.data("index"));
            notificationTemplateTable.expanded = true;
            notificationTemplateTable.expandedUuid = row.uuid;
        }
    });

    notificationTemplateTable.on("load-success.bs.table", function(e, data) {
        let publisherSelectInput = $("#createNotificationAlertPublisherInput");
        publisherSelectInput.html("");
        $.each(data, function(i, publisher) {
            publisherSelectInput.append($("<option/>", { value: publisher.uuid, text: publisher.name }));
        });
        if (notificationTemplateTable.expanded === true) {
            $.each(data, function(i, publisher) {
                if (publisher.uuid === notificationTemplateTable.expandedUuid) {
                    notificationTemplateTable.bootstrapTable("expandRow", i);
                }
            });
        }
    });

    const teamTable = $("#teamsTable");
    teamTable.on("click-row.bs.table", function(e, row, $tr) {
        if ($tr.next().is("tr.detail-view")) {
            teamTable.bootstrapTable("collapseRow", $tr.data("index"));
            teamTable.expanded = false;
        } else {
            teamTable.bootstrapTable("collapseAllRows");
            teamTable.bootstrapTable("expandRow", $tr.data("index"));
            teamTable.expanded = true;
            teamTable.expandedUuid = row.uuid;
        }
    });

    teamTable.on("load-success.bs.table", function(e, data) {
        teamData(data); // Cache team data for other views/purposes
        if (teamTable.expanded === true) {
            $.each(data, function(i, team) {
                if (team.uuid === teamTable.expandedUuid) {
                    teamTable.bootstrapTable("expandRow", i);
                }
            });
        }
    });

    const ldapUserTable = $('#ldapUsersTable');
    ldapUserTable.on("click-row.bs.table", function(e, row, $tr) {
        if ($tr.next().is("tr.detail-view")) {
            ldapUserTable.bootstrapTable("collapseRow", $tr.data("index"));
            ldapUserTable.expanded = false;
        } else {
            ldapUserTable.bootstrapTable("collapseAllRows");
            ldapUserTable.bootstrapTable("expandRow", $tr.data("index"));
            ldapUserTable.expanded = true;
            ldapUserTable.expandedUuid = row.username;
        }
    });

    ldapUserTable.on("load-success.bs.table", function(e, data) {
        if (ldapUserTable.expanded === true) {
            $.each(data, function(i, user) {
                if (user.username === ldapUserTable.expandedUuid) {
                    ldapUserTable.bootstrapTable("expandRow", i);
                }
            });
        }
    });

    const managedUserTable = $("#managedUsersTable");
    managedUserTable.on("click-row.bs.table", function(e, row, $tr) {
        if ($tr.next().is("tr.detail-view")) {
            managedUserTable.bootstrapTable("collapseRow", $tr.data("index"));
            managedUserTable.expanded = false;
        } else {
            managedUserTable.bootstrapTable("collapseAllRows");
            managedUserTable.bootstrapTable("expandRow", $tr.data("index"));
            managedUserTable.expanded = true;
            managedUserTable.expandedUuid = row.username;
        }
    });

    managedUserTable.on("load-success.bs.table", function(e, data) {
        if (managedUserTable.expanded === true) {
            $.each(data, function(i, user) {
                if (user.username === managedUserTable.expandedUuid) {
                    managedUserTable.bootstrapTable("expandRow", i);
                }
            });
        }
    });

    let token = $auth.decodeToken($auth.getToken());
    if ($auth.hasPermission($auth.ACCESS_MANAGEMENT, token)) {
        $("#teamsTable").bootstrapTable("refresh", {url: $rest.contextPath() + URL_TEAM, silent: true});
        $("#ldapUsersTable").bootstrapTable("refresh", {url: $rest.contextPath() + URL_USER_LDAP, silent: true});
        $("#managedUsersTable").bootstrapTable("refresh", {url: $rest.contextPath() + URL_USER_MANAGED, silent: true});
        $("#permissionsTable").bootstrapTable("refresh", {url: $rest.contextPath() + URL_PERMISSION, silent: true});
        $("#permissionListingTable").bootstrapTable("refresh", {url: $rest.contextPath() + URL_PERMISSION, silent: true});
    }
    if ($auth.hasPermission($auth.SYSTEM_CONFIGURATION, token)) {
        $rest.getConfigProperties(populateConfigProperties);
    }
    if ($auth.hasPermission($auth.VIEW_PORTFOLIO, token)) {
        $("#notificationRuleProjectTable").bootstrapTable("refresh", {url: $rest.contextPath() + URL_PROJECT, silent: true});
    }

    /**
     * Sets the title of the page based on what menu item was clicked.
     */
    $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        let target = $(e.target).attr("href");
        let adminTitleElement = $("#admin-title");
        let adminTitleString = $(target).attr("data-admin-title");
        if (adminTitleString) {
            adminTitleElement.html('<i class="fa fa-cog" aria-hidden="true"></i> ' + adminTitleString);
        } else {
            adminTitleElement.html('<i class="fa fa-cog" aria-hidden="true"></i> Administration');
        }
    });

    /**
     * Highlights the active item in the admin accordion menu.
     */
    $(".list-group .list-group-item").click(function(e) {
        $(".list-group .list-group-item").removeClass("active");
        $(e.target).addClass("active");
    });

    /**
     * Listen for if the button to update config properties is clicked. This function ensures
     * that the group-name assigned to the inputs being iterated on matches the group-name of
     * the button that was clicked.
     */
    $(".btn-config-property").on("click", function() {
        let groupName = $(this).data("group-name");
        $("input[data-group-name]").each(function() {
            if (groupName === $(this).data("group-name")) {
                let propertyValue = $(this).val();
                if ($(this).attr("type") === "checkbox") {
                    propertyValue = $(this).is(":checked");
                }
                $rest.updateConfigProperty($(this).data("group-name"), $(this).data("property-name"), propertyValue);
            }
        });
    });

    $(".scannerToggleButton").change(function() {
        let propertyValue = $(this).is(":checked");
        $rest.updateConfigProperty($(this).data("group-name"), $(this).data("property-name"), propertyValue);
    });

});