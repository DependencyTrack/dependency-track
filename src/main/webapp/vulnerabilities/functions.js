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
 * Called by bootstrap table to format the data in the vulnerability table.
 */
function formatVulnerabilityTable(res) {
    for (let i=0; i<res.length; i++) {
        let vulnurl = "../vulnerability/?source=" + res[i].source + "&vulnId=" + res[i].vulnId;
        res[i].vulnerabilityhref = "<a href=\"" + vulnurl + "\">" + res[i].vulnId + "</a>";

        if (res[i].hasOwnProperty("cwe")) {
            res[i].cwefield = "CWE-" + res[i].cwe.cweId + " " + res[i].cwe.name;
        }

        if (res[i].hasOwnProperty("source")) {
            res[i].sourceLabel = formatSourceLabel(res[i].source);
        }

        if (res[i].hasOwnProperty("severity")) {
            res[i].severityLabel = formatSeverityLabel(res[i].severity);
        }
    }
    return res;
}

function formatSourceLabel(source) {
    let sourceClass = "label-source-" + source.toLowerCase();
    return `<span class="label ${sourceClass}">${source}</span>`;
}

function formatSeverityLabel(severity) {
    let severityLabel = capitalize(severity);
    let severityClass = "severity-" + severity.toLowerCase() + "-bg";

    return `
     <div style="height:24px;margin:-4px;">
        <div class="${severityClass} text-center pull-left" style="width:24px; height:24px; color:#ffffff">
            <i class="fa fa-bug" style="font-size:12px; padding:6px" aria-hidden="true"></i>
         </div>
         <div class="text-center pull-left" style="height:24px;">
             <div style="font-size:12px; padding:4px"><span class="severity-value">${severityLabel}</span></div>
         </div>
     </div>`;
}

/**
 * Setup events and trigger other stuff when the page is loaded and ready.
 */
$(document).ready(function () {

});