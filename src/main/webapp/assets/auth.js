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

const $auth = function() {
};

$auth.BOM_UPLOAD             = "BOM_UPLOAD";
$auth.SCAN_UPLOAD            = "SCAN_UPLOAD";
$auth.VIEW_PORTFOLIO         = "VIEW_PORTFOLIO";
$auth.PORTFOLIO_MANAGEMENT   = "PORTFOLIO_MANAGEMENT";
$auth.ACCESS_MANAGEMENT      = "ACCESS_MANAGEMENT";
$auth.VULNERABILITY_ANALYSIS = "VULNERABILITY_ANALYSIS";
$auth.SYSTEM_CONFIGURATION   = "SYSTEM_CONFIGURATION";

/**
 * Determines if the current logged in user has a specific permission.
 * If the decodedToken is not passed, the function will automatically
 * retrieve and decode it.
 */
$auth.hasPermission = function hasPermission(permission, decodedToken) {
    let token = decodedToken;
    if (!decodedToken) {
        token = $auth.decodeToken($auth.getToken());
    }
    if (token !== null && token.hasOwnProperty("permissions")) {
        let permissions = token.permissions.split(",");
        for (let i = 0; i < permissions.length; i++) {
            if (permissions[i] === permission) {
                return true;
            }
        }
    }
    return false;
};

/**
 * Returns the decoded token as a JSON object.
 */
$auth.decodeToken = function decodeToken(token) {
    let base64Url = token.split('.')[1];
    let base64 = base64Url.replace('-', '+').replace('_', '/');
    return JSON.parse(window.atob(base64));
};

/**
 * Retrieves the token from session storage.
 */
$auth.getToken = function getToken() {
    return $.sessionStorage.get("token");
};
