/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */

"use strict";

/**
 * Constants
 */
const CONTENT_TYPE_JSON = "application/json";
//const CONTENT_TYPE_TEXT = "text/plain";
//const TOTAL_COUNT_HEADER = "X-Total-Count";
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
const URL_METRICS = "api/v1/metrics";

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
            /**
             * @param {Object} response the JSON response
             * @param response.results
             * @param response.results.project
             * @returns {*}
             */
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
            /**
             * @param {Object} response the JSON response
             * @param response.results
             * @param response.results.component
             * @returns {*}
             */
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
            /**
             * @param {Object} response the JSON response
             * @param response.results
             * @param response.results.vulnerability
             * @returns {*}
             */
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
            /**
             * @param {Object} response the JSON response
             * @param response.results
             * @param response.results.license
             * @returns {*}
             */
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
        url: $rest.contextPath() + URL_PROJECT + "/" + uuid,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
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
 * Service called when a component is updated.
 */
$rest.updateComponent = function updateComponent(uuid, name, version, group, description, license, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_COMPONENT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({uuid: uuid, name: name, version: version, group: group, description: description, license: license}),
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
 * Service called when a component is deleted.
 */
$rest.deleteComponent = function deleteProject(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_COMPONENT + "/" + uuid,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
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
        url: $rest.contextPath() + URL_LICENSE + "?offset=0&limit=1000",
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
        url: $rest.contextPath() + URL_VULNERABILITY + "/" + uuid,
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
 * Service called to retrieve vulnerability metrics
 */
$rest.getVulnerabilityMetrics = function getVulnerabilityMetrics(successCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/vulnerability",
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            }
        }
    });
};

/**
 * Service called to retrieve current metrics for the entire portfolio
 */
$rest.getPortfolioCurrentMetrics = function getPortfolioCurrentMetrics(successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/portfolio/current",
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
 * Service called to retrieve historical metrics for the entire portfolio
 */
$rest.getPortfolioMetrics = function getPortfolioMetrics(daysBack, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/portfolio/" + daysBack + "/days",
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
 * Service called to retrieve current metrics for a specific project
 */
$rest.getProjectCurrentMetrics = function getProjectCurrentMetrics(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/project/" + uuid + "/current",
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
 * Service called to retrieve historical metrics for a specific project
 */
$rest.getProjectMetrics = function getProjectMetrics(uuid, daysBack, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/project/" + uuid + "/days/" + daysBack,
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
 * Service called to retrieve current metrics for a specific component
 */
$rest.getComponentCurrentMetrics = function getComponentCurrentMetrics(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/component/" + uuid + "/current",
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
 * Service called to retrieve historical metrics for a specific component
 */
$rest.getComponentMetrics = function getComponentMetrics(uuid, daysBack, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/component/" + uuid + "/days/" + daysBack,
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
 * Service called to refresh metrics for the entire portfolio
 */
$rest.refreshPortfolioMetrics = function refreshPortfolioMetrics(successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/portfolio/refresh",
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
 * Service called to refresh metrics for a specific project
 */
$rest.refreshProjectMetrics = function refreshProjectMetrics(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/project/" + uuid + "/refresh",
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
 * Service called to refresh metrics for a specific component
 */
$rest.refreshComponentMetrics = function refreshComponentMetrics(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/component/" + uuid + "/refresh",
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
 * Service called when a team is created.
 */
$rest.createTeam = function createTeam(name, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_TEAM,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({name: name}),
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
 * Service called when a team is updated.
 */
$rest.updateTeam = function updateTeam(uuid, name, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_TEAM,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({uuid: uuid, name: name}),
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
 * Service called when a team is deleted.
 */
$rest.deleteTeam = function deleteTeam(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_TEAM,
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
 * Service called when a managed user is created.
 */
$rest.createManagedUser = function createManagedUser(username, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER_MANAGED,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({username: username}),
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
 * Service called when a managed user is updated.
 * //todo: complete this service on client and server side
 */
$rest.updateManagedUser = function updateManagedUser(username, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER_MANAGED,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({username: username}),
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
 * Service called when a managed user is deleted.
 */
$rest.deleteManagedUser = function deleteManagedUser(username, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER_MANAGED,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
        data: JSON.stringify({username: username}),
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
 * Service called when a LDAP user is created.
 */
$rest.createLdapUser = function createLdapUser(username, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER_LDAP,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({username: username}),
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
 * Service called when a LDAP user is deleted.
 */
$rest.deleteLdapUser = function deleteLdapUser(username, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER_LDAP,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_DELETE,
        data: JSON.stringify({username: username}),
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
 * Service called when an API key is created.
 */
$rest.addApiKey = function addApiKey(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_TEAM + "/" + uuid + "/key",
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        statusCode: {
            201: function(data) {
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
        error: function(xhr, ajaxOptions, thrownError){
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called when an API key is regenerated.
 */
$rest.regenerateApiKey = function regenerateApiKey(apikey, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_TEAM + "/key/" + apikey,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
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
        error: function(xhr, ajaxOptions, thrownError){
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called when an API key is deleted.
 */
$rest.deleteApiKey = function deleteApiKey(apikey, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_TEAM + "/key/" + apikey,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_DELETE,
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
        error: function(xhr, ajaxOptions, thrownError){
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called when a user is assigned to a team.
 */
$rest.assignUserToTeam = function assignUserToTeam(username, teamuuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER + "/" + username + "/membership",
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({uuid: teamuuid}),
        statusCode: {
            200: function (data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            304: function (data) {
                // The user is already a member of the specified team
                // Intentionally left blank
            },
            404: function (data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
            if (failCallback) {
                $rest.callbackValidator(failCallback(xhr, ajaxOptions, thrownError));
            }
        }
    });
};

/**
 * Service called when a user is un-assigned from a team.
 */
$rest.removeUserFromTeam = function removeUserFromTeam(username, teamuuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER + "/" + username + "/membership",
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_DELETE,
        data: JSON.stringify({uuid: teamuuid}),
        statusCode: {
            200: function (data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            304: function (data) {
                // The user was not a member of the specified team
                // Intentionally left blank
            },
            404: function (data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        },
        error: function(xhr, ajaxOptions, thrownError){
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
        if (jwt !== null) {
            xhr.setRequestHeader("Authorization", "Bearer " + jwt);
        }
    },
    error: function(xhr, textStatus) {
        if(textStatus === "timeout") {
            $common.displayErrorModal(xhr, "The server is not responding. Please try again or contact the administrator.");
        }
    },
    timeout: 10000,
    statusCode: {
        /**
         * @method $ jQuery selector
         */
        200: function() {
            $("#navbar-container").css("display", "block");
            $("#sidebar").css("display", "block");
            $(".main").css("display", "block");
            $("#modal-login").modal("hide");
        },
        400: function(xhr) {
            $common.displayErrorModal(xhr, "The request made was incorrect or not in the proper format (400).");
        },
        /**
         * @method $ jQuery selector
         */
        401: function() {
            $("#navbar-container").css("display", "none");
            $("#sidebar").css("display", "none");
            $(".main").css("display", "none");
            $("#modal-login").modal("show");
            $("#username").focus();
        },
        403: function(xhr) {
            $common.displayErrorModal(xhr, "The request is forbidden (403).");
        },
        404: function(xhr) {
            $common.displayErrorModal(xhr, "The requested object could not be found (404).");
        },
        409: function(xhr) {
            $common.displayErrorModal(xhr, "A conflict occurred preventing the request from being processed (409).");
        },
        500: function() {
            $common.displayErrorModal(null, "An unexpected error occurred. Please contact the Dependency-Track administrator for assistance (500).");
        }
    }
});
