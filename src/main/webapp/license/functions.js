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
    let license = Bind(data, {
        name: ".licenseName",
        licenseText: ".licenseText",
        standardLicenseTemplate: ".templateText",
        standardLicenseHeader: ".headerText",
        licenseId: ".licenseId",
        isOsiApproved: ".isOsiApproved",
        isDeprecatedLicenseId: ".isDeprecatedLicenseId",
        licenseComments: ".licenseComments",
        seeAlso: {
            dom: '.seeAlso',
            transform: function (value) {
                return "<a href=\"" + this.safe(value) + "\">" + this.safe(value) + "</a><br/>";
            },
        }
    });
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