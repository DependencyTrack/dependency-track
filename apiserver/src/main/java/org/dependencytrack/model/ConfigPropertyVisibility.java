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
package org.dependencytrack.model;

/// Controls the visibility of a [ConfigPropertyConstants] value.
///
/// Does **not** control who can write. Writing config properties *always*
/// requires `SYSTEM_CONFIGURATION[_UPDATE]` permissions.
///
/// @since 5.1.0
public enum ConfigPropertyVisibility {

    /// Only visible to principals with the `SYSTEM_CONFIGURATION[_READ]` permission.
    /// Should be the default unless a specific use case requires broader visibility.
    RESTRICTED,

    /// Visible to any authenticated principal, no permission required.
    /// Use for values that may contain organization-internal yet non-confidential
    /// references not meant for unauthenticated parties.
    INTERNAL,

    /// Visible to anyone, including unauthenticated parties.
    PUBLIC

}