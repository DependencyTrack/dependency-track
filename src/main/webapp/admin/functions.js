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
    }
    return res;
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
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {

    // Initialize all tooltips
    $('[data-toggle="tooltip"]').tooltip();

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
});