/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */

"use strict";

/**
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {

    // Initialize all tooltips
    $('[data-toggle="tooltip"]').tooltip();

    // Listen for if the button to create a team is clicked
    $('#createTeamCreateButton').on('click', createTeam);

    // Listen for if the button to create a user is clicked
    $('#createUserCreateButton').on('click', createUser);

    // Listen for if the button to assign a team to a user is clicked
    $('#assignTeamToUser').on('click', assignTeamToUser);

    // When modal closes, clear out the input fields
    $('#modalCreateTeam').on('hidden.bs.modal', function () {
        $('#createTeamNameInput').val('');
    });
    $('#modalCreateUser').on('hidden.bs.modal', function () {
        $('#createUserNameInput').val('');
    });

    // When modal is about to be shown, update the data model
    const teamsMembershipTable = $('#teamsMembershipTable');
    $('#modalAssignTeamToUser').on('show.bs.modal', function () {
        teamsMembershipTable.bootstrapTable('load', teamData());
        teamsMembershipTable.bootstrapTable('refresh', {silent: true});
    });

    const teamTable = $('#teamsTable');
    teamTable.on("click-row.bs.table", function(e, row, $tr) {
        if ($tr.next().is('tr.detail-view')) {
            teamTable.bootstrapTable('collapseRow', $tr.data('index'));
            teamTable.expanded = false;
        } else {
            teamTable.bootstrapTable('collapseAllRows');
            teamTable.bootstrapTable('expandRow', $tr.data('index'));
            teamTable.expanded = true;
            teamTable.expandedUuid = row.uuid;
        }
    });

    teamTable.on("load-success.bs.table", function(e, data) {
        teamData(data); // Cache team data for other views/purposes
        if (teamTable.expanded == true) {
            $.each(data, function(i, team) {
                if (team.uuid == teamTable.expandedUuid) {
                    teamTable.bootstrapTable('expandRow', i);
                }
            });
        }
    });

    const userTable = $('#usersTable');
    userTable.on("click-row.bs.table", function(e, row, $tr) {
        if ($tr.next().is('tr.detail-view')) {
            userTable.bootstrapTable('collapseRow', $tr.data('index'));
            userTable.expanded = false;
        } else {
            userTable.bootstrapTable('collapseAllRows');
            userTable.bootstrapTable('expandRow', $tr.data('index'));
            userTable.expanded = true;
            userTable.expandedUuid = row.username;
        }
    });

    userTable.on("load-success.bs.table", function(e, data) {
        if (userTable.expanded == true) {
            $.each(data, function(i, user) {
                if (user.username == userTable.expandedUuid) {
                    userTable.bootstrapTable('expandRow', i);
                }
            });
        }
    });
});

function teamData(data) {
    if (data === undefined) {
        data = JSON.parse(localStorage['teamData']);
    } else {
        localStorage['teamData'] = JSON.stringify(data);
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
        if (res[i].ldapUsers === undefined) {
            res[i].membersNum = 0;
        } else {
            res[i].membersNum = res[i].ldapUsers.length;
        }

        if (res[i].hakmaster == true) {
            res[i].hakmasterIcon = "&#10004;";
        } else {
            res[i].hakmasterIcon = "";
        }
    }
    return res;
}

/**
 * Called by bootstrap table to format the data in the ldap users table.
 */
function formatUserTable(res) {
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
    let hakmasterChecked = '';
    if (row.hakmaster == true) {
        hakmasterChecked = 'checked="checked"';
    }
    let html = [];

    let apiKeysHtml = '';
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


    let membersHtml = '';
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
            <label for="inputApiKeys">Hakmaster</label>
            <input type="checkbox" class="checkbox-inline" id="inputTeamHakmaster-${row.uuid}" placeholder="Hakmaster" ${hakmasterChecked} data-team-uuid="${row.uuid}">
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
        $('#inputTeamName-${row.uuid}').keypress(debounce(updateTeam, 750));
        $('#inputTeamHakmaster-${row.uuid}').change(updateTeam);
        $('#deleteTeam-${row.uuid}').on('click', deleteTeam);
    </script>
`;
    html.push(template);
    return html.join('');
}

/**
 * Function called by bootstrap table when row is clicked/touched, and
 * expanded. This function handles the dynamic creation of the expanded
 * view with simple inline templates.
 */
function userDetailFormatter(index, row) {
    let html = [];

    let teamsHtml = '';
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


    let template = `
    <div class="col-sm-6 col-md-6">
    <form id="form-${row.uuid}">
        <div class="form-group">
            <label for="inputApiKeys">Team Membership</label>
            <ul class="list-group" id="inputApiKeys">
                ${teamsHtml}
            </ul>
        </div> 
    </div>
    <div class="col-sm-6 col-md-6">
        <div class="form-group">
            <label for="inputTeamMembers">Statistics</label>
            <ul class="list-group" id="inputTeamMembers">
                Last logon:
            </ul>
        </div>
        <button type="button" class="btn btn-danger pull-right" id="deleteUser-${row.username}" data-user-username="${row.username}">Delete User</button>
    </form>
    </div>
    <script type="text/javascript">
        $('#deleteUser-${row.username}').on('click', deleteUser);
        $('#add-user-${row.username}-to-team').on('click', function () {
            $("#assignTeamToUser").attr('data-username', $(this).data("username")); // Assign the username to the data-username attribute of the 'Update' button
        });
    </script>
`;
    html.push(template);
    return html.join('');
}

/**
 * Service called when a team is created.
 */
function createTeam() {
    const inputField = $('#createTeamNameInput');
    const teamName = inputField.val();
    $.ajax({
        url: contextPath() + URL_TEAM,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({name: teamName}),
        statusCode: {
            201: function(data) {
                $('#teamsTable').bootstrapTable('refresh', {silent: true});
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
    inputField.val('');
}

/**
 * Service called when a team is updated.
 */
function updateTeam() {
    const teamUuid = $(this).data("team-uuid");
    const teamName = $('#inputTeamName-' + teamUuid).val();
    const isHakmaster = $('#inputTeamHakmaster-' + teamUuid).is(':checked');
    $.ajax({
        url: contextPath() + URL_TEAM,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({uuid: teamUuid, name: teamName, hakmaster: isHakmaster}),
        statusCode: {
            200: function(data) {
                $('#teamsTable').bootstrapTable('refresh', {silent: true});
            },
            404: function(data) {
                //todo: the uuid of the team could not be found
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
}

/**
 * Service called when a team is deleted.
 */
function deleteTeam() {
    const teamUuid = $(this).data("team-uuid");
    $.ajax({
        url: contextPath() + URL_TEAM,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
        data: JSON.stringify({uuid: teamUuid}),
        statusCode: {
            204: function(data) {
                const teamTable = $('#teamsTable');
                teamTable.expanded = false;
                teamTable.bootstrapTable('collapseAllRows');
                teamTable.bootstrapTable('refresh', {silent: true});
            },
            404: function(data) {
                //todo: the uuid of the team could not be found
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
}

/**
 * Service called when an API key is created.
 */
function addApiKey(uuid) {
    $.ajax({
        url: contextPath() + URL_TEAM + "/" + uuid + "/key",
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        statusCode: {
            201: function(data) {
                $('#teamsTable').bootstrapTable('refresh', {silent: true});
            },
            404: function(data) {
                //todo: the uuid of the team could not be found
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
}

/**
 * Service called when an API key is regenerated.
 */
function regenerateApiKey(apikey) {
    $.ajax({
        url: contextPath() + URL_TEAM + "/key/" + apikey,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        statusCode: {
            200: function(data) {
                $('#apikey-' + apikey).html(data.key);
                $('#apikey-' + apikey).attr("id","apikey-" + data.key);
                $('#regen-' + apikey).attr("id","regen-" + data.key);
                $('#regen-' + data.key).attr("onclick","regenerateApiKey('" + data.key + "')");
                $('#delete-' + apikey).attr("id","delete-" + data.key);
                $('#delete-' + data.key).attr("onclick","deleteApiKey('" + data.key + "')");
                $('#teamsTable').bootstrapTable('refresh', {silent: true});
            },
            404: function(data) {
                //todo: the api key could not be found
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
}

/**
 * Service called when an API key is deleted.
 */
function deleteApiKey(apikey) {
    $.ajax({
        url: contextPath() + URL_TEAM + "/key/" + apikey,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
        statusCode: {
            204: function (data) {
                $('#container-apikey-' + apikey).remove();
                $('#teamsTable').bootstrapTable('refresh', {silent: true});
            },
            404: function (data) {
                //todo: the api key could not be found
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
}

/**
 * Service called when a user is created.
 */
function createUser() {
    const inputField = $('#createUserNameInput');
    const username = inputField.val();
    $.ajax({
        url: contextPath() + URL_USER,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({username: username}),
        statusCode: {
            201: function (data) {
                $('#usersTable').bootstrapTable('refresh', {silent: true});
            },
            400: function (data) {
                //todo: username cannot be blank
            },
            409: function (data) {
                //todo: a user with the same username already exists
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
    inputField.val('');
}

/**
 * Service called when a user is deleted.
 */
function deleteUser() {
    const username = $(this).data("user-username");
    $.ajax({
        url: contextPath() + URL_USER,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
        data: JSON.stringify({username: username}),
        statusCode: {
            204: function (data) {
                const userTable = $('#usersTable');
                userTable.expanded = false;
                userTable.bootstrapTable('collapseAllRows');
                userTable.bootstrapTable('refresh', {silent: true});
            },
            404: function (data) {
                //todo: the user could not be found
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
}

/**
 * Service called when teams are assigned to a user
 */
function assignTeamToUser() {
    const username = $('#assignTeamToUser').attr('data-username');
    const selections = $('#teamsMembershipTable').bootstrapTable('getAllSelections');
    for (let i = 0; i < selections.length; i++) {
        let uuid = selections[i].uuid;
        $.ajax({
            url: contextPath() + URL_USER + "/" + username + "/membership",
            contentType: CONTENT_TYPE_JSON,
            dataType: DATA_TYPE,
            type: METHOD_POST,
            data: JSON.stringify({uuid: uuid}),
            statusCode: {
                200: function (data) {
                    $('#teamsTable').bootstrapTable('refresh', {silent: true});
                    $('#usersTable').bootstrapTable('refresh', {silent: true});
                },
                304: function (data) {
                    //todo: The user is already a member of the specified team
                },
                404: function (data) {
                    //todo: The user or team could not be found
                }
            },
            error: function(xhr, ajaxOptions, thrownError){
                console.log("failed");
            }
        });
    }
}

function removeTeamMembership(uuid, username) {
    $.ajax({
        url: contextPath() + URL_USER + "/" + username + "/membership",
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
        data: JSON.stringify({uuid: uuid}),
        statusCode: {
            200: function (data) {
                $('#container-' + uuid + '-' + username + '-membership').remove();
                $('#teamsTable').bootstrapTable('refresh', {silent: true});
                $('#usersTable').bootstrapTable('refresh', {silent: true});
            },
            304: function (data) {
                //todo: The user was not a member of the specified team
            },
            404: function (data) {
                //todo: the user or team could not be found
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
}