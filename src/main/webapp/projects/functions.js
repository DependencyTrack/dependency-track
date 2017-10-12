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
    let projectsTable = $("#projectsTable");
    for (let i=0; i<res.length; i++) {
        let projecturl = "../project/?uuid=" + res[i].uuid;
        res[i].projecthref = "<a href=\"" + projecturl + "\">" + filterXSS(res[i].name) + "</a>";

        $rest.getProjectCurrentMetrics(res[i].uuid, function (data) {
            res[i].vulnerabilities = generateSeverityProgressBar(data.critical, data.high, data.medium, data.low);
            projectsTable.bootstrapTable('updateRow', {
                index: i,
                row: res[i]
            });
        });
    }
    return res;
}

function projectCreated(data) {
    $("#projectsTable").bootstrapTable("refresh", {silent: true});
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
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {

    // Initialize all tooltips
    $('[data-toggle="tooltip"]').tooltip();

    // Listen for if the button to create a project is clicked
    $("#createProjectCreateButton").on("click", function() {
        const name = $("#createProjectNameInput").val();
        const version = $("#createProjectVersionInput").val();
        const description = $("#createProjectDescriptionInput").val();
        const tags = csvStringToObjectArray($("#createProjectTagsInput").val());
        $rest.createProject(name, version, description, tags, projectCreated);
        clearInputFields();
    });

    // When modal closes, clear out the input fields
    $("#modalCreateProject").on("hidden.bs.modal", function() {
        $("#createProjectNameInput").val("");
    });

});