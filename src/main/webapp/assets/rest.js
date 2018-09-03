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
const URL_FORCE_PW_CHANGE = "api/v1/user/forceChangePassword";
const URL_TEAM = "api/v1/team";
const URL_USER = "api/v1/user";
const URL_USER_LDAP = "api/v1/user/ldap";
const URL_USER_MANAGED = "api/v1/user/managed";
const URL_USER_SELF = "api/v1/user/self";
const URL_PERMISSION = "api/v1/permission";
const URL_PROJECT = "api/v1/project";
const URL_FINDING = "api/v1/finding";
const URL_LICENSE = "api/v1/license";
const URL_CWE = "api/v1/cwe";
const URL_COMPONENT = "api/v1/component";
const URL_DEPENDENCY = "api/v1/dependency";
const URL_VULNERABILITY = "api/v1/vulnerability";
const URL_ANALYSIS = "api/v1/analysis";
const URL_SEARCH = "api/v1/search";
const URL_METRICS = "api/v1/metrics";
const URL_CALCULATOR_CVSS = "api/v1/calculator/cvss";
const URL_REPOSITORY = "api/v1/repository";
const URL_CONFIG_PROPERTY = "api/v1/configProperty";
const URL_NOTIFICATION_PUBLISHER = "api/v1/notification/publisher";
const URL_NOTIFICATION_RULE = "api/v1/notification/rule";

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
            },
            403: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            }
        }
    });
};

/**
 * Performs a forced password change using the specified username and password to assert authentication along with
 * the new and confirmed password.
 */
$rest.forceChangePassword = function forceChangePassword(username, currentPassword, newPassword, confirmPassword, successCallback, failCallback) {
    $.ajax({
        type: METHOD_POST,
        url: $rest.contextPath() + URL_FORCE_PW_CHANGE,
        data: ({username: username, password: currentPassword, newPassword: newPassword, confirmPassword: confirmPassword}),
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
            },
            403: function(data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
            },
            406: function(data) {
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
 * Updates user info (if available)
 */
$rest.updatePrincipalSelf = function getPrincipalSelf(fullname, email, newPassword, confirmPassword, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER_SELF,
        contentType: CONTENT_TYPE_JSON,
        type: METHOD_POST,
        data: JSON.stringify({fullname: fullname, email: email, newPassword: newPassword, confirmPassword: confirmPassword}),
        statusCode: {
            200: function(data) {
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
 * Service called to retrieve a list of all projects with the specified name
 */
$rest.getProjectVersions = function getProjectVersions(name, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PROJECT + "?name=" + name,
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
$rest.createComponent = function createComponent(name, version, group, description, license,
                                                 filename, classifier, purl, cpe, copyright,
                                                 md5, sha1, sha256, sha512, sha3_256, sha3_512,
                                                 successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_COMPONENT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({name: name, version: version, group:group, description: description, license: license,
            filename: filename, classifier: classifier, purl: purl, cpe: cpe, copyright: copyright,
            md5: md5, sha1: sha1, sha256: sha256, sha512: sha512, sha3_256: sha3_256, sha3_512: sha3_512}),
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
 * Service called when a component is created. Same as createComponent but minimal fields. Check usage before changing.
 */
$rest.createComponentMinimalFields = function createComponent(name, version, group, description, license,
                                                 successCallback, failCallback) {
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
$rest.updateComponent = function updateComponent(uuid, name, version, group, description, license,
                                                 filename, classifier, purl, cpe, copyright,
                                                 md5, sha1, sha256, sha512, sha3_256, sha3_512,
                                                 successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_COMPONENT,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({uuid: uuid, name: name, version: version, group:group, description: description, license: license,
            filename: filename, classifier: classifier, purl: purl, cpe: cpe, copyright: copyright,
            md5: md5, sha1: sha1, sha256: sha256, sha512: sha512, sha3_256: sha3_256, sha3_512: sha3_512}),
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
 * Service called when one or more components is added as a dependency to a project.
 */
$rest.addDependency = function addDependency(projectUuid, componentUuids, notes, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_DEPENDENCY,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({projectUuid: projectUuid, componentUuids: componentUuids, notes: notes}),
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
 * Service called when one or more components are removed as a dependency from a project.
 */
$rest.removeDependency = function removeDependency(projectUuid, componentUuids, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_DEPENDENCY,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_DELETE,
        data: JSON.stringify({projectUuid: projectUuid, componentUuids: componentUuids}),
        statusCode: {
            204: function(data) {
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
 * Service called to retrieve CVSS (v2/v3) scores (based on the vector passed)
 */
$rest.getCvssScores = function getCvssScores(vector, successCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_CALCULATOR_CVSS + "?vector=" + vector,
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
 * Service called to retrieve all licenses
 */
$rest.getCwes = function getCwes(successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_CWE + "?offset=0&limit=1000",
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
 * Service called to retrieve a specific CWE
 */
$rest.getCwe = function getCwe(cweId, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_CWE + "/" + cweId,
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
 * Service called to retrieve all findings for the specified project
 */
$rest.getProjectFindings = function getProjectFindings(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_FINDING + "/project/" + uuid,
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
 * Service called to retrieve current metrics for a specific dependency
 */
$rest.getDependencyCurrentMetrics = function getDependencyCurrentMetrics(projectUuid, componentUuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/project/" + projectUuid + "/component/" + componentUuid + "/current",
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
 * Service called to retrieve historical metrics for a specific dependency
 */
$rest.getDependencyMetrics = function getDependencyMetrics(projectUuid, componentUuid, daysBack, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/project/" + projectUuid + "/component/" + componentUuid + "/days/" + daysBack,
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
 * Service called to refresh metrics for a specific dependency
 */
$rest.refreshDependencyMetrics = function refreshDependencyMetrics(projectUuid, componentUuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_METRICS + "/project/" + projectUuid + "/component/" + componentUuid + "/refresh",
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
 * Service called to retrieve analysis decisions
 */
$rest.getAnalysis = function getAnalysis(projectUuid, componentUuid, vulnerabilityUuid, successCallback, failCallback) {
    let queryString;
    if (projectUuid == null) {
        queryString = "?component=" + componentUuid + "&vulnerability=" + vulnerabilityUuid
    } else {
        queryString = "?project=" + projectUuid + "&component=" + componentUuid + "&vulnerability=" + vulnerabilityUuid;
    }
    $.ajax({
        url: $rest.contextPath() + URL_ANALYSIS + queryString,
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
 * Service called to retrieve analysis decisions
 */
$rest.makeAnalysis = function makeAnalysis(projectUuid, componentUuid, vulnerabilityUuid, analysisState, comment, isSuppressed, successCallback, failCallback) {
    let url = (projectUuid != null) ? URL_ANALYSIS : URL_ANALYSIS + "/global";
    $.ajax({
        url: $rest.contextPath() + url,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({project: projectUuid, component: componentUuid, vulnerability: vulnerabilityUuid, analysisState: analysisState, comment: comment, isSuppressed: isSuppressed}),
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
$rest.createManagedUser = function createManagedUser(username, fullname, email, newPassword, confirmPassword, forcePasswordChange, nonExpiryPassword, suspended, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER_MANAGED,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({username: username, fullname: fullname, email: email, newPassword: newPassword, confirmPassword: confirmPassword, forcePasswordChange: forcePasswordChange, nonExpiryPassword: nonExpiryPassword, suspended: suspended}),
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
 */
$rest.updateManagedUser = function updateManagedUser(username, fullname, email, newPassword, confirmPassword, forcePasswordChange, nonExpiryPassword, suspended, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_USER_MANAGED,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({username: username, fullname: fullname, email: email, newPassword: newPassword, confirmPassword: confirmPassword, forcePasswordChange: forcePasswordChange, nonExpiryPassword: nonExpiryPassword, suspended: suspended}),
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
 * Service called when a permission is assigned.
 */
$rest.assignPermissionToUser = function assignPermissionToUser(username, permissionName, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PERMISSION + "/" + permissionName + "/user/" + username,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
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
 * Service called when a permission is un-assigned.
 */
$rest.removePermissionFromUser = function removePermissionFromUser(username, permissionName, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PERMISSION + "/" + permissionName + "/user/" + username,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_DELETE,
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
 * Service called when a permission is assigned.
 */
$rest.assignPermissionToTeam = function assignPermissionToTeam(uuid, permissionName, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PERMISSION + "/" + permissionName + "/team/" + uuid,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
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
 * Service called when a permission is un-assigned.
 */
$rest.removePermissionFromTeam = function removePermissionFromTeam(uuid, permissionName, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_PERMISSION + "/" + permissionName + "/team/" + uuid,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_DELETE,
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
 * Service called when a vulnerability is created.
 */
$rest.createVulnerability = function createVulnerability(vulnId, title, subTitle, description, recommendation,
                                                         references, credits, created, published, updated, cweId,
                                                         cvssV2Vector, cvssV3Vector, vulnerableVersions, patchedVersions,
                                                         successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_VULNERABILITY,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({vulnId: vulnId, title: title, subTitle: subTitle, description: description,
            recommendation: recommendation, references: references, credits: credits, created: created,
            published: published, updated: updated, cwe: {cweId: cweId}, cvssV2Vector: cvssV2Vector,
            cvssV3Vector: cvssV3Vector, vulnerableVersions: vulnerableVersions, patchedVersions: patchedVersions}),
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
 * Service called to retrieve the latest version of a tracked component
 */
$rest.getLatestFromRepository = function getProject(packageUrl, successCallback, failCallback) {
    let queryString = "?purl=" + encodeURIComponent(packageUrl);
    $.ajax({
        url: $rest.contextPath() + URL_REPOSITORY + "/latest" + queryString,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            204: function(data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            400: function(data) {
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
 * Service called to retrieve config properties
 */
$rest.getConfigProperties = function getConfigProperties(successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_CONFIG_PROPERTY,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_GET,
        statusCode: {
            200: function (data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
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
 * Service called when a config property is updated
 */
$rest.updateConfigProperty = function updateConfigProperty(groupName, propertyName, propertyValue, successCallback, failCallback) {
    if ($common.isEmpty(groupName) || $common.isEmpty(propertyName)) {
        return;
    }
    $.ajax({
        url: $rest.contextPath() + URL_CONFIG_PROPERTY,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({groupName: groupName, propertyName: propertyName, propertyValue: propertyValue}),
        statusCode: {
            200: function (data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
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
 * Service called when a notification rule is created
 */
$rest.createNotificationRule = function createNotificationRule(name, scope, level, publisherUuid, successCallback, failCallback) {
    if ($common.isEmpty(name)) {
        return;
    }
    $.ajax({
        url: $rest.contextPath() + URL_NOTIFICATION_RULE,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_PUT,
        data: JSON.stringify({name: name, scope: scope, notificationLevel: level, publisher: { uuid: publisherUuid } }),
        statusCode: {
            201: function (data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
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
 * Service called when a notification rule is updated
 */
$rest.updateNotificationRule = function updateNotificationRule(uuid, name, level, publisherConfig, notifyOn, successCallback, failCallback) {
    if ($common.isEmpty(name)) {
        return;
    }
    $.ajax({
        url: $rest.contextPath() + URL_NOTIFICATION_RULE,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        data: JSON.stringify({uuid: uuid, name: name, notificationLevel: level, publisherConfig: publisherConfig, notifyOn: notifyOn}),
        statusCode: {
            200: function (data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
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
 * Service called when a notification rule is deleted
 */
$rest.deleteNotificationRule = function deleteNotificationRule(uuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_NOTIFICATION_RULE,
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
 * Service called when a project is added to a notification rule
 */
$rest.addProjectToNotificationRule = function addProjectToNotificationRule(ruleUuid, projectUuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_NOTIFICATION_RULE + "/" + ruleUuid + "/project/" + projectUuid,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_POST,
        statusCode: {
            200: function (data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            304: function (data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
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
 * Service called when a project is removed from a notification rule
 */
$rest.removeProjectFromNotificationRule = function removeProjectFromNotificationRule(ruleUuid, projectUuid, successCallback, failCallback) {
    $.ajax({
        url: $rest.contextPath() + URL_NOTIFICATION_RULE + "/" + ruleUuid + "/project/" + projectUuid,
        contentType: CONTENT_TYPE_JSON,
        dataType: DATA_TYPE,
        type: METHOD_DELETE,
        statusCode: {
            200: function (data) {
                if (successCallback) {
                    $rest.callbackValidator(successCallback(data));
                }
            },
            304: function (data) {
                if (failCallback) {
                    $rest.callbackValidator(failCallback(data));
                }
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
    complete: function(xhr, textStatus) {
        if ($.getUrlVar("debug")) {
            console.log("Status: " + xhr.status);
            (xhr.responseJSON) ? console.log(xhr.responseJSON) : console.log(xhr.responseText);
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
