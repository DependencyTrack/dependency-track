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