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
 * Constants
 */
const CONTENT_TYPE_JSON = "application/json";
const CONTENT_TYPE_TEXT = "text/plain";
const TOTAL_COUNT_HEADER = "X-Total-Count";
const DATA_TYPE = "json";
const METHOD_GET = "GET";
const METHOD_POST = "POST";
const METHOD_PUT = "PUT";
const METHOD_DELETE = "DELETE";
const URL_ABOUT = "api/version";
const URL_LOGIN = "api/v1/user/login";
const URL_TEAM = "api/v1/team";
const URL_USER = "api/v1/user";
const URL_USER_LDAP = "api/v1/user/ldap";
const URL_USER_MANAGED = "api/v1/user/managed";
const URL_USER_SELF = "api/v1/user/self";
const URL_PROJECT = "api/v1/project";
const URL_LICENSE = "api/v1/license";
const URL_COMPONENT = "api/v1/component";
const URL_VULNERABILITY = "api/v1/vulnerability";
const URL_SEARCH = "api/v1/search";

const $rest = function() {
};

$rest.contextPath = function contextPath() {
    let path = $("meta[name=context-path]").attr("content");
    return path.endsWith("/") ? path : path + "/";
};

/**
 * Retrieves search suggestions by utilizing Bloodhound which calls
 * the server-side search resource.
 */
$rest.smartsearchProject = function smartsearch() {
    return new Bloodhound({
        datumTokenizer: Bloodhound.tokenizers.obj.whitespace("name"),
        queryTokenizer: Bloodhound.tokenizers.whitespace,
        remote: {
            url: $rest.contextPath() + URL_SEARCH + "/%QUERY",
            wildcard: '%QUERY',
            filter: function(response) {
                return response.results.project;
            }
        }
    });
};

/**
 * Retrieves search suggestions by utilizing Bloodhound which calls
 * the server-side search resource.
 */
$rest.smartsearchComponent = function smartsearch() {
    return new Bloodhound({
        datumTokenizer: Bloodhound.tokenizers.obj.whitespace("name"),
        queryTokenizer: Bloodhound.tokenizers.whitespace,
        remote: {
            url: $rest.contextPath() + URL_SEARCH + "/%QUERY",
            wildcard: '%QUERY',
            filter: function(response) {
                return response.results.component;
            }
        }
    });
};

/**
 * Retrieves search suggestions by utilizing Bloodhound which calls
 * the server-side search resource.
 */
$rest.smartsearchVulnerability = function smartsearch() {
    return new Bloodhound({
        datumTokenizer: Bloodhound.tokenizers.obj.whitespace("vulnId"),
        queryTokenizer: Bloodhound.tokenizers.whitespace,
        remote: {
            url: $rest.contextPath() + URL_SEARCH + "/%QUERY",
            wildcard: '%QUERY',
            filter: function(response) {
                return response.results.vulnerability;
            }
        }
    });
};

/**
 * Retrieves search suggestions by utilizing Bloodhound which calls
 * the server-side search resource.
 */
$rest.smartsearchLicense = function smartsearch() {
    return new Bloodhound({
        datumTokenizer: Bloodhound.tokenizers.obj.whitespace("name"),
        queryTokenizer: Bloodhound.tokenizers.whitespace,
        remote: {
            url: $rest.contextPath() + URL_SEARCH + "/%QUERY",
            wildcard: '%QUERY',
            filter: function(response) {
                return response.results.license;
            }
        }
    });
};

/**
 * Validates the specified parameter is a function that
 * can be called.
 */
$rest.callbackValidator = function callbackValidator(callback) {
    if (null !== callback && typeof callback === "function") {
        return callback;
    }
    return new function () {
    };
};

/**
 * Retrieves version information from the resource
 */
$rest.getVersion = function getVersion(successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_ABOUT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        success: function (data) {
            if (successCallback) {
                $rest.callbackValidator(successCallback(data));
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Performs a login using the specified username and password
 */
$rest.login = function login(username, password, successCallback, failCallback) {
    $.ajax({
        type: METHOD_POST,
        url: $rest.contextPath() + URL_LOGIN,
        data: ({username: username, password: password}),
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            401: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        }
    });
};

/**
 * Retrieves user info (if available)
 */
$rest.getPrincipalSelf = function getPrincipalSelf(successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER_SELF,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_GET,
        success: function (data) {
            if (successCallback) {
                $rest.callbackValidator(successCallback(data));
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called when a project is created.
 */
$rest.createProject = function createProject(name, version, description, tags, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PROJECT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({name: name, version: version, description: description, tags: tags}),
        statusCode: {
            201: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called to retrieve all projects
 */
$rest.getProjects = function getProjects(successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PROJECT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        }
    });
};

/**
 * Service called to retrieve a specific project
 */
$rest.getProject = function getProject(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PROJECT + "/" + uuid,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called when a project is updated.
 */
$rest.updateProject = function updateProject(uuid, name, version, description, tags, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PROJECT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({uuid: uuid, name: name, version: version, description: description, tags: tags}),
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called when a project is deleted.
 */
$rest.deleteProject = function deleteProject(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PROJECT,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
        data: JSON.stringify({uuid: uuid}),
        statusCode: {
            204: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called when a component is created.
 */
$rest.createComponent = function createComponent(name, version, group, description, license, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_COMPONENT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({name: name, version: version, group:group, description: description, license: license}),
        statusCode: {
            201: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called to retrieve all components
 */
$rest.getComponents = function getProjects(successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_COMPONENT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        }
    });
};

/**
 * Service called to retrieve a specific project
 */
$rest.getComponent = function getProject(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_COMPONENT + "/" + uuid,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called to retrieve all licenses
 */
$rest.getLicenses = function getLicenses(successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_LICENSE,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        }
    });
};

/**
 * Service called to retrieve a specific license
 */
$rest.getLicense = function getLicense(licenseId, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_LICENSE + "/" + licenseId,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        }
    });
};

/**
 * Service called to retrieve a specific vulnerability
 */
$rest.getVulnerabilityByUuid = function getVulnerabilityByUuid(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_VULNERABILITY + "/uuid/" + uuid,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called to retrieve a specific vulnerability
 */
$rest.getVulnerabilityByVulnId = function getVulnerabilityByName(source, vulnId, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_VULNERABILITY + "/source/" + source + "/vuln/" + vulnId,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            404: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError) {
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

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
            $(".main").css("display", "block");
            $("#modal-login").modal("hide");
        },
        401: function() {
            $("#navbar-container").css("display", "none");
            $("#sidebar").css("display", "none");
            $(".main").css("display", "none");
            $("#modal-login").modal("show");
            $("#username").focus();
        }
    }
});
