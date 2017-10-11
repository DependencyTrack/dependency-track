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
    let componentsTable = $("#componentsTable");
    for (let i=0; i<res.length; i++) {
        let componenturl = "../component/?uuid=" + res[i].uuid;
        res[i].componenthref = "<a href=\"" + componenturl + "\">" + filterXSS(res[i].name) + "</a>";
        res[i].version = filterXSS(res[i].version);
        res[i].group = filterXSS(res[i].group);

        if (res[i].hasOwnProperty("resolvedLicense")) {
            let licenseurl = "../license/?licenseId=" + res[i].resolvedLicense.licenseId;
            res[i].license = "<a href=\"" + licenseurl + "\">" + filterXSS(res[i].resolvedLicense.licenseId) + "</a>";
        }

        $rest.getComponentCurrentMetrics(res[i].uuid, function (data) {
            res[i].vulnerabilities = generateSeverityProgressBar(data.critical, data.high, data.medium, data.low);
            componentsTable.bootstrapTable('updateRow', {
                index: i,
                row: res[i]
            });
        });
    }
    return res;
}

function componentCreated(data) {
    $("#componentsTable").bootstrapTable("refresh", {silent: true});
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

/**
 * Populates select/dropdown with list of all licenses.
 */
function populateLicenseData(data) {
    let select = $("#createComponentLicenseSelect");
    $.each(data, function() {
        select.append($("<option />").val(this.licenseId).text(this.name));
    });
    select.selectpicker('refresh');
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready.
 */
$(document).ready(function () {

    // Initialize all tooltips
    //$('[data-toggle="tooltip"]').tooltip();

    $rest.getLicenses(populateLicenseData);

    // Listen for if the button to create a project is clicked
    $("#createComponentCreateButton").on("click", function() {
        const name = $("#createComponentNameInput").val();
        const version = $("#createComponentVersionInput").val();
        const group = $("#createComponentGroupInput").val();
        const description = $("#createComponentDescriptionInput").val();
        const license = $("#createComponentLicenseSelect").val();
        $rest.createComponent(name, version, group, description, license, componentCreated);
        clearInputFields();
    });

    // When modal closes, clear out the input fields
    $("#modalCreateComponent").on("hidden.bs.modal", function() {
        clearInputFields();
    });

});