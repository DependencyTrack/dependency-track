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
package org.dependencytrack.auth.saml;

/// Thrown when a SAML message or metadata document is refused.
///
/// The message describes the failed check for logging. It must never be returned to clients.
///
/// @since 5.3.0
public class SamlException extends Exception {

    public SamlException(String message) {
        super(message);
    }

    public SamlException(String message, Throwable cause) {
        super(message, cause);
    }
}
