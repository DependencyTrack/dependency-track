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
 * Called by bootstrap table to format the data in the components table.
 */
function formatComponentsTable(res) {
    for (let i=0; i<res.length; i++) {
        let projecturl = "../project?uuid=" + res[i].uuid;
        res[i].projecthref = "<a href=\"" + projecturl + "\">" + res[i].name + "</a>";
    }
    return res;
}

/**
 * Called when a component is successfully created
 */
function componentCreated() {
    $("#projectsTable").bootstrapTable("refresh", {silent: true});
    clearInputFields();
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
    $("#createProjectNameInput").val("");
    $("#createProjectVersionInput").val("");
    $("#createProjectDescriptionInput").val("");
    $("#createProjectTagsInput").val("");
}

function populateProjectData(data) {
    $("#projectTitle").html(data.name);
    if (data.version) {
        $("#projectVersion").html(" &#x025B8; " + data.version);
    }
}

function populateLicenseData(data) {
    let select = $("#createComponentLicenseSelect");
    $.each(data, function() {
        select.append($("<option />").val(this.licenseId).text(this.name));
    });
    select.selectpicker('refresh');
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready
 */
$(document).ready(function () {

    let uuid = $.getUrlVar('uuid');

    $rest.getProject(uuid, populateProjectData);
    $rest.getLicenses(populateLicenseData);

    // Initialize all tooltips
    //$('[data-toggle="tooltip"]').tooltip();

    // Listen for when the button to create a project is clicked
    $("#createComponentCreateButton").on("click", function () {
        const name = $("#createComponentNameInput").val();
        const version = $("#createComponentVersionInput").val();
        const group = $("#createComponentGroupInput").val();
        const description = $("#createComponentDescriptionInput").val();
        const licenseId = $("#createComponentLicenseSelect").val();
        $rest.createComponent(name, version, group, description, licenseId, componentCreated(), clearInputFields());
    });

    // When modal closes, clear out the input fields
    $("#modalCreateComponent").on("hidden.bs.modal", function () {
        $("#createComponentNameInput").val("");
    });

});