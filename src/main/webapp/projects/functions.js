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
 * Called by bootstrap table to format the data in the projects table.
 */
function formatProjectsTable(res) {
    for (let i=0; i<res.length; i++) {
        let projecturl = "../project?uuid=" + res[i].uuid;
        res[i].projecthref = "<a href=\"" + projecturl + "\">" + res[i].name + "</a>";
    }
    return res;
}

/**
 * Service called when a project is created.
 */
function createProject() {
    const name = $("#createProjectNameInput").val();
    const version = $("#createProjectVersionInput").val();
    const description = $("#createProjectDescriptionInput").val();
    const tags = tagsStringToObjectArray($("#createProjectTagsInput").val());
    console.log("name: " + name);
    console.log("version: " + version);
    console.log("description: " + description);
    console.log("tags: " + tags);
    $.ajax({
        url: contextPath() + URL_PROJECT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({name: name, version: version, description: description, tags: tags}),
        statusCode: {
            201: function(data) {
                $("#projectsTable").bootstrapTable("refresh", {silent: true});
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            console.log("failed");
        }
    });
    clearInputFields();
}

/**
 * Given a comma-separated string of tags, creates an
 * array of tag objects.
 */
function tagsStringToObjectArray(tagsString) {
    let tagsArray = [];
    if (!isEmpty(tagsString)) {
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
    $("#createProjectNameInput").val("");
    $("#createProjectVersionInput").val("");
    $("#createProjectDescriptionInput").val("");
    $("#createProjectTagsInput").val("");
}

/**
 * Service called when a project is updated.
 */
function updateProject() {
    const uuid = $(this).data("project-uuid");
    const name = $("#inputProjectName-" + uuid).val();
    const version = $("#inputProjectVersion-" + uuid).val();
    const description = $("#inputProjectDescription-" + uuid).val();
    const tags = $("#inputProjectTags-" + uuid).val();
    $.ajax({
        url: contextPath() + URL_PROJECT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({uuid: uuid, name: name, version: version, description: description, tags: tags}),
        statusCode: {
            200: function(data) {
                $("#projectsTable").bootstrapTable("refresh", {silent: true});
            },
            404: function(data) {
                //todo: the uuid of the project could not be found
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
}

/**
 * Service called when a project is deleted.
 */
function deleteProject() {
    const uuid = $(this).data("project-uuid");
    $.ajax({
        url: contextPath() + URL_PROJECT,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
        data: JSON.stringify({uuid: uuid}),
        statusCode: {
            204: function(data) {
                const projectsTable = $('#projectsTable');
                projectsTable.expanded = false;
                projectsTable.bootstrapTable("collapseAllRows");
                projectsTable.bootstrapTable("refresh", {silent: true});
            },
            404: function(data) {
                //todo: the uuid of the project could not be found
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            console.log("failed");
        }
    });
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {

    // Initialize all tooltips
    $('[data-toggle="tooltip"]').tooltip();

    // Listen for if the button to create a project is clicked
    $("#createProjectCreateButton").on("click", createProject);

    // When modal closes, clear out the input fields
    $("#modalCreateProject").on("hidden.bs.modal", function () {
        $("#createProjectNameInput").val("");
    });

});