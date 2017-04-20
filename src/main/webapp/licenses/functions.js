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
 * Called by bootstrap table to format the data in the licenses table.
 */
function formatLicensesTable(res) {
    for (let i=0; i<res.length; i++) {

        if (res[i].isOsiApproved === true) {
            res[i].osiApprovedLabel = '<i class="fa fa-check-square-o" aria-hidden="true"></i>';
        } else {
            res[i].osiApprovedLabel = '';
        }

        let licenseurl = "../license/?licenseId=" + res[i].licenseId;
        res[i].licensehref = "<a href=\"" + licenseurl + "\">" + res[i].licenseId + "</a>";
    }
    return res;
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready.
 */
$(document).ready(function () {

});