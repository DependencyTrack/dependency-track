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
package org.dependencytrack.capabilities;

import org.glassfish.hk2.api.ServiceLocator;

import java.util.Map;

/**
 * @since 5.0.0
 */
public interface CapabilityProvider {

    String namespace();

    Map<String, Object> capabilities();

    /// Whether the namespace is also served to clients that are not authenticated, for example the login page.
    ///
    /// Public capabilities are visible to anyone who can reach the server. Only make a namespace public when
    /// clients need it before login, and when its flags reveal nothing that helps an attacker,
    /// such as versions, host names, or other configuration details.
    ///
    /// @since 5.3.0
    default boolean isPublic() {
        return false;
    }

    default void init(ServiceLocator serviceLocator) {}
}
