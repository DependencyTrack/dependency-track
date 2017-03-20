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
var CONTENT_TYPE_JSON = "application/json";
var CONTENT_TYPE_TEXT = "text/plain";
var DATA_TYPE = "json";
var METHOD_GET = "GET";
var METHOD_POST = "POST";
var METHOD_PUT = "PUT";
var METHOD_DELETE = "DELETE";
var URL_ABOUT = "/version";
var URL_LOGIN = "/v1/user/login";
var URL_TEAM = "/v1/team";
var URL_USER = "/v1/user";
var URL_USER_SELF = "/v1/user/self";


function contextPath() {
    return $('meta[name=api-path]').attr("content");
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
                $('#nav-logout').css('display', "none");
            }
        }
    });
}

/**
 * Generic handler for all AJAX requests
 */
$.ajaxSetup({
    beforeSend: function(xhr) {
        var jwt = $.sessionStorage.get("token");
        if (jwt != null) {
            xhr.setRequestHeader("Authorization", "Bearer " + jwt);
        }
    },
    statusCode: {
        200: function() {
            $('#navbar-container').css("display", "block");
            $('#main').css("display", "block");
            $('#modal-login').modal("hide");
        },
        401: function() {
            $('#navbar-container').css("display", "none");
            $('#main').css("display", "none");
            $('#modal-login').modal("show");
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
    var username = $("#username").val();
    var password = $("#password").val();
    $.ajax({
        type: METHOD_POST,
        url: contextPath() + URL_LOGIN,
        data: ({username: username, password: password}),
        success: function (data) {
            $.sessionStorage.set("token", data);
        },
        statusCode: {
            200: function(){
                $('#navbar-container').css("display", "block");
                $('#main').css("display", "block");
                $('#modal-login').modal("hide");
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
    $('#systemAppName').html(data.application);
    $('#systemAppVersion').html(data.version);
    $('#systemAppTimestamp').html(data.timestamp);
    $('#dcAppName').html(data.dependencyCheck.application);
    $('#dcAppVersion').html(data.dependencyCheck.version);
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