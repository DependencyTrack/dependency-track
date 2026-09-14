/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.auth;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;

/// @since 5.2.0
public final class OAuthErrorException extends RuntimeException {

    private final ErrorObject errorObject;

    public OAuthErrorException(ErrorObject errorObject) {
        super(errorObject.getDescription());
        this.errorObject = errorObject;
    }

    public static OAuthErrorException invalidRequest(String description) {
        return new OAuthErrorException(OAuth2Error.INVALID_REQUEST.setDescription(description));
    }

    public static OAuthErrorException refused() {
        return invalidRequest("The subject token cannot be exchanged");
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }
}
