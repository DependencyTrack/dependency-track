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
 * Copyright (c) Sam Gleske. All Rights Reserved.
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.Config;
import alpine.model.ManagedUser;
import alpine.server.resources.AlpineResource;
import java.security.Principal;
import org.dependencytrack.persistence.QueryManager;

/**
 * An extension of AlpineResource that provides all of the same features but for
 * Dependency-Track also enables disabled authentication and authorization from
 * Alpine.  Anonymous is treated the same as admin user or Administrators team.
 * @since 4.7.0
 */
public abstract class ExtendedAlpineResource extends AlpineResource {
    /**
     * Returns the principal for who initiated the request.  If
     * ALPINE_ENFORCE_AUTHENTICATION is disabled then the admin ManagedUser is
     * returned.
     * @return a Principal object
     * @see alpine.model.ApiKey
     * @see alpine.model.LdapUser
     * @see alpine.model.ManagedUser
     */
    @Override
    protected Principal getPrincipal() {
        if (!Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHENTICATION)) {
            // Authentication is not enabled, try returning admin principal
            try (QueryManager qm = new QueryManager()) {
                final ManagedUser user = qm.getManagedUser("admin");
                if (user != null) {
                    return (Principal) user;
                }
            }
        }
        return super.getPrincipal();
    }

    /**
     * Convenience method that returns true if the principal has the specified permission,
     * or false if not.  If ALPINE_ENFORCE_AUTHENTICATION is disabled then the
     * true will always be returned.
     * @param permission the permission to check
     * @return true if principal has permission assigned, false if not
     */
    @Override
    protected boolean hasPermission(final String permission) {
        if (!Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHENTICATION)) {
            return true;
        }
        return super.hasPermission(permission);
    }
}
