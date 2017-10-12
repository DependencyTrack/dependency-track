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

const $common = function() {
};

/**
 * Returns a function, that, as long as it continues to be invoked, will not
 * be triggered. The function will be called after it stops being called for
 * N milliseconds. If `immediate` is passed, trigger the function on the
 * leading edge, instead of the trailing.
 *
 * https://davidwalsh.name/javascript-debounce-function
 */
$common.debounce = function debounce(func, wait, immediate) {
    let timeout;
    return function() {
        let context = this, args = arguments;
        let later = function() {
            timeout = null;
            if (!immediate) {
                func.apply(context, args);
            }
        };
        let callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) {
            func.apply(context, args);
        }
    };
};

/**
 * Useful for parsing HREF's
 */
$common.getLocation = function getLocation(href) {
    if (href === null) {
        href = window.location;
    }
    let location = document.createElement("a");
    location.href = href;
    return location;
};

/**
 * Check if a string is empty, null or undefined
 */
$common.isEmpty = function isEmpty(string) {
    return (!string || 0 === string.length);
};

/**
 * Check if a string is blank, null or undefined I use:
 */
$common.isBlank = function isBlank(string) {
    return (!string || /^\s*$/.test(string));
};

//######################################################################################################################
/**
 * Called after we have verified that a user is authenticated (if authentication is enabled)
 */
function initialize(data) {
    //todo: check permissions - populate admin and other navigational things accordingly
    $rest.getVersion(
        function onVersionSuccess(data) {
            // Populates teh system modeal with general app info
            $("#systemAppName").html(data.application);
            $("#systemAppVersion").html(data.version);
            $("#systemAppTimestamp").html(data.timestamp);
            $("#dcAppName").html(data.dependencyCheck.application);
            $("#dcAppVersion").html(data.dependencyCheck.version);

            if (!$.sessionStorage.isSet("token")) {
                $("#nav-logout").css("display", "none");
            }
        }
    );
}

/**
 * Logout function removes the stored jwt token and reloads the page, which will
 * force the login modal to display
 */
function logout() {
    $.sessionStorage.remove("token");
    location.reload();
}
//######################################################################################################################
/**
 * Executed when the login button is clicked. Prevent the form from actually being
 * submitted and uses javascript to submit the form info.
 */
$("#login-form").submit(function(event) {
    event.preventDefault();
    let usernameElement = $("#username");
    let username = usernameElement.val();
    let passwordElement = $("#password");
    let password = passwordElement.val();
    $rest.login(username, password, function(data) {
        $.sessionStorage.set("token", data);
        $("#navbar-container").css("display", "block");
        $("#sidebar").css("display", "block");
        $(".main").css("display", "block");
        $("#modal-login").modal("hide");
        initialize();
    }, function(data) {
        // todo: Display invalid username or password somewhere
    });
    usernameElement.val("");
    passwordElement.val("");
});

/**
 * Executed when the DOM is ready for JavaScript to be executed.
 */
$(document).ready(function () {

    // Initialize all tooltips
    $('[data-toggle="tooltip"]').tooltip();

    // Get information about the current logged in user (if available)
    $rest.getPrincipalSelf(initialize);
    let contextPath = $rest.contextPath();

    /**
     * Function that adds the 'active' class to one of the buttons in
     * the sidebar based on the data-sidebar attribute in the pages' body.
     */
    (function() {
        let nav = document.getElementById("sidebar"),
            anchors = nav.getElementsByTagName("a"),
            bodySidebar = document.body.getAttribute("data-sidebar");

        for (let i = 0; i < anchors.length; i++) {
            if(bodySidebar === anchors[i].getAttribute("data-sidebar")) {
                anchors[i].parentElement.className = "active";
            }
        }
    })();

    $("#smart-search .typeahead").typeahead(null,
        {
            name: "project",
            source: $rest.smartsearchProject(),
            display: "name",
            templates: {
                header: '<h4 class="section-title">Projects</h4>',
                suggestion: function (data) {
                    return '<a class="tt-suggestion-item" href="' + contextPath + 'project/?uuid=' + data.uuid + '">' + data.name + '</a>';
                }
            }
        },
        {
            name: "component",
            source: $rest.smartsearchComponent(),
            display: "name",
            templates: {
                header: '<h4 class="section-title">Components</h4>',
                suggestion: function (data) {
                    return '<a class="tt-suggestion-item" href="' + contextPath + 'component/?uuid=' + data.uuid + '">' + data.name + '</a>';
                }
            }
        },
        {
            name: "vulnerability",
            source: $rest.smartsearchVulnerability(),
            display: "vulnId",
            templates: {
                header: '<h4 class="section-title">Vulnerabilities</h4>',
                suggestion: function (data) {
                    return '<a class="tt-suggestion-item" href="' + contextPath + 'vulnerability/?source=' + data.source + '&vulnId=' + data.vulnId + '">' + data.vulnId + '</a>';
                }
            }
        },
        {
            name: "license",
            source: $rest.smartsearchLicense(),
            display: "name",
            templates: {
                header: '<h4 class="section-title">Licenses</h4>',
                suggestion: function (data) {
                    return '<a class="tt-suggestion-item" href="' + contextPath + 'license/?licenseId=' + data.licenseId + '">' + data.name + '</a>';
                }
            }
        }
    );

});

/**
 * Displays an error modal with the specified message. If the responseText
 * from an AJAX response is available, that text will be used. If not, the
 * fallback message will be used instead.
 */
function displayErrorModal(xhr, fallbackMessage) {
    let message = fallbackMessage;
    if (xhr && xhr.responseText && xhr.responseText.trim()) {
        message = xhr.responseText.trim();
    }
    $("#modal-genericError").modal("show");
    $("#modal-genericErrorContent").html(message);
}

/**
 * Creates a multi-color progress bar consisting of the number of
 * critical, high, medium, and low severity vulnerabilities.
 */
function generateSeverityProgressBar(critical, high, medium, low) {
    let percentCritical = (critical/(critical+high+medium+low))*100;
    let percentHigh = (high/(critical+high+medium+low))*100;
    let percentMedium = (medium/(critical+high+medium+low))*100;
    let percentLow = (low/(critical+high+medium+low))*100;
    let block = '<span class="progress">';
    if (critical > 0) {
        block += '<div class="progress-bar severity-critical-bg" data-toggle="tooltip" data-placement="top" title="Critical: ' + critical + ' (' + Math.round(percentCritical*10)/10 + '%)" style="width:' + percentCritical+ '%">' + critical + '</div>';
    }
    if (high > 0) {
        block += '<div class="progress-bar severity-high-bg" data-toggle="tooltip" data-placement="top" title="High: ' + high + ' (' + Math.round(percentHigh * 10) / 10 + '%)" style="width:' + percentHigh + '%">' + high + '</div>';
    }
    if (medium > 0) {
        block += '<div class="progress-bar severity-medium-bg" data-toggle="tooltip" data-placement="top" title="Medium: ' + medium + ' (' + Math.round(percentMedium * 10) / 10 + '%)" style="width:' + percentMedium + '%">' + medium + '</div>';
    }
    if (low > 0) {
        block += '<div class="progress-bar severity-low-bg" data-toggle="tooltip" data-placement="top" title="Low: ' + low + ' (' + Math.round(percentLow * 10) / 10 + '%)" style="width:' + percentLow + '%">' + low + '</div>';
    }
    if (critical === 0 && high === 0 && medium === 0 && low === 0) {
        block += '<div class="progress-bar severity-info-bg" data-toggle="tooltip" data-placement="top" title="No Vulnerabilities Detected" style="width:100%">0</div>';
    }
    block += '</span>';
    return block;
}

/**
 * Given a UNIX timestamp, this function will return a formatted date.
 * i.e. 15 Jan 2017
 */
function formatTimestamp(timestamp) {
    let date = new Date(timestamp);
    let months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return date.getDate() + " " + months[date.getMonth()] + " " + date.getFullYear();
}

/**
 * Formats and returns a specialized label for a vulnerability source (NVD, NSP, VulnDB, etc).
 */
function formatSourceLabel(source) {
    let sourceClass = "label-source-" + source.toLowerCase();
    return `<span class="label ${sourceClass}">${source}</span>`;
}

/**
 * Formats and returns a specialized label for the severity of a vulnerability.
 */
function formatSeverityLabel(severity) {
    if (!severity) {
        return;
    }
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
 * Changes the first letter to uppercase and the remaining letters to lowercase.
 */
function capitalize(string) {
    if (string && string.length > 2) {
        return string.charAt(0).toUpperCase() + string.slice(1).toLowerCase();
    }
    return string;
}

/**
 * Given a comma-separated string, creates an array of objects.
 */
function csvStringToObjectArray(csvString) {
    let csvArray = [];
    if (!$common.isEmpty(csvString)) {
        let tmpArray = csvString.split(",");
        for (let i in tmpArray) {
            csvArray.push({name: tmpArray[i]});
        }
    }
    return csvArray;
}

/**
 * Defines JSON characters that need to be escaped when data is used in HTML
 */
const __entityMap = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "/": "&#x2F;"
};

/**
 * Perform client-side JSON escaping
 */

function toHtml(string) {
    if(typeof string === "string") {
        return String(string).replace(/[&<>"'\/]/g, function (s) {
            return __entityMap[s];
        });
    } else {
        return string;
    }
}

/**
 * Extends JQuery
 */
$.extend({

    /**
     * Retrieves the querystring, parses it.
     */
    getUrlVars: function() {
        let vars = [], hash;
        let hashes = window.location.href.replace("#", "").slice(window.location.href.indexOf("?") + 1).split("&");
        for(let i = 0; i < hashes.length; i++) {
            hash = hashes[i].split("=");
            vars.push(hash[0]);
            vars[hash[0]] = hash[1];
        }
        return vars;
    },

    /**
     * Provides a function to extract a param from the querystring.
     */
    getUrlVar: function(name) {
        return $.getUrlVars()[name];
    }
});
