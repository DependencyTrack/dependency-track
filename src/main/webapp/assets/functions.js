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

/**
 * Constants
 */
const CONTENT_TYPE_JSON = "application/json";
const CONTENT_TYPE_TEXT = "text/plain";
const DATA_TYPE = "json";
const METHOD_GET = "GET";
const METHOD_POST = "POST";
const METHOD_PUT = "PUT";
const METHOD_DELETE = "DELETE";
const URL_ABOUT = "/version";
const URL_LOGIN = "/v1/user/login";
const URL_TEAM = "/v1/team";
const URL_USER = "/v1/user";
const URL_USER_LDAP = "/v1/user/ldap";
const URL_USER_MANAGED = "/v1/user/managed";
const URL_USER_SELF = "/v1/user/self";


function contextPath() {
    return $("meta[name=api-path]").attr("content");
}

/**
 * Called after we have verified that a user is authenticated (if authentication is enabled)
 */
function initialize() {
    callVersionResource();
}

/**
 * Retrieves user info (if available)
 */
function callUserSelfResource() {
    $.ajax({
        url: contextPath() + URL_USER_SELF,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_GET,
        success: function (data) {
            //todo: check permissions - populate admin and other navigational things accordingly

            initialize();
        }
    });
}

function callVersionResource() {
    $.ajax({
        url: contextPath() + URL_ABOUT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        success: function (data) {
            populateAboutModal(data);
            if (!$.sessionStorage.isSet("token")) {
                $("#nav-logout").css("display", "none");
            }
        }
    });
}

/**
 * Generic handler for all AJAX requests
 */
$.ajaxSetup({
    beforeSend: function(xhr) {
        let jwt = $.sessionStorage.get("token");
        if (jwt != null) {
            xhr.setRequestHeader("Authorization", "Bearer " + jwt);
        }
    },
    statusCode: {
        200: function() {
            $("#navbar-container").css("display", "block");
            $("#sidebar").css("display", "block");
            $("#main").css("display", "block");
            $("#modal-login").modal("hide");
        },
        401: function() {
            $("#navbar-container").css("display", "none");
            $("#sidebar").css("display", "none");
            $("#main").css("display", "none");
            $("#modal-login").modal("show");
            $("#username").focus();
        }
    }
});

/**
 * Executed when the login button is clicked. Prevent the form from actually being
 * submitted and uses javascript to submit the form info.
 */
$("#login-form").submit(function(event) {
    event.preventDefault();
    submitLogin();
});

/**
 * Submits the actual login form data, retrieves jwt token (if successful) and places it
 * in html5 sessionStorage.
 */
function submitLogin() {
    let username = $("#username").val();
    let password = $("#password").val();
    $.ajax({
        type: METHOD_POST,
        url: contextPath() + URL_LOGIN,
        data: ({username: username, password: password}),
        success: function (data) {
            $.sessionStorage.set("token", data);
        },
        statusCode: {
            200: function(){
                $("#navbar-container").css("display", "block");
                $("#sidebar").css("display", "block");
                $("#main").css("display", "block");
                $("#modal-login").modal("hide");
                initialize();
            },
            401: function(){
                $("#username").val("");
                $("#password").val("");
            }
        }
    });
}

/**
 * Logout function removes the stored jwt token and reloads the page, which will
 * force the login modal to display
 */
function logout() {
    $.sessionStorage.remove("token");
    location.reload();
}

/**
 * Populates the system modal with general app info
 */
function populateAboutModal(data) {
    $("#systemAppName").html(data.application);
    $("#systemAppVersion").html(data.version);
    $("#systemAppTimestamp").html(data.timestamp);
    $("#dcAppName").html(data.dependencyCheck.application);
    $("#dcAppVersion").html(data.dependencyCheck.version);
}

/**
 * Returns a function, that, as long as it continues to be invoked, will not
 * be triggered. The function will be called after it stops being called for
 * N milliseconds. If `immediate` is passed, trigger the function on the
 * leading edge, instead of the trailing.
 *
 * https://davidwalsh.name/javascript-debounce-function
 */
function debounce(func, wait, immediate) {
    let timeout;
    return function() {
        let context = this, args = arguments;
        let later = function() {
            timeout = null;
            if (!immediate) func.apply(context, args);
        };
        let callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) func.apply(context, args);
    };
}

/**
 * Executed when the DOM is ready for JavaScript to be executed.
 */
$(document).ready(function () {
    /* Prevents focus loss on login modal */
    /* This has the unforntunate effect of flashing the modal visible even if it shouldn't be
     $('#modal-login').modal({
     backdrop: 'static',
     keyboard: false
     });
     */
    $('[data-toggle="tooltip"]').tooltip();
    callUserSelfResource();
});