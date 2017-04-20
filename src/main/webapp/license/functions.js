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

function populateLicenseData(data) {
    $("#licenseName").text(data.name);
    $("#licenseText").text(data.licenseText);
    $("#templateText").text(data.standardLicenseTemplate);
    $("#headerText").text(data.standardLicenseHeader);

    $("#generalLicenseName").text(data.name);
    $("#generalLicenseId").text(data.licenseId);
    $("#generalOsiApproved").text(data.isOsiApproved);
    $("#generalDeprecated").text(data.isDeprecatedLicenseId);
    $("#generalComments").text(data.licenseComments);

    let seeAlsoField = "";
    if (data.seeAlso !== null) {
        for (let i = 0; i < data.seeAlso.length; i++) {
            seeAlsoField += "<a href=\"" + data.seeAlso[i] + "\">" + data.seeAlso[i] + "</a><br/>";
        }
    }
    $("#generalSeeAlso").html(seeAlsoField);

    if (data.isOsiApproved === true) {
        $("#generalOsiLogo").css("display", "block");
    }
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready.
 */
$(document).ready(function () {

    let licenseId = $.getUrlVar("licenseId");
    $rest.getLicense(licenseId, populateLicenseData);

});