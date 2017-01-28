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
package org.owasp.dependencytrack.filters;

import org.owasp.dependencytrack.Config;
import org.owasp.dependencytrack.auth.AuthenticationNotRequired;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;
import java.lang.reflect.Method;

@Provider
public class AuthenticationFeature implements DynamicFeature {

    private static final boolean ENFORCE_AUTHENTICATION = Config.getInstance().getPropertyAsBoolean(Config.Key.ENFORCE_AUTHENTICATION);

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        if (ENFORCE_AUTHENTICATION) {
            Method method = resourceInfo.getResourceMethod();
            if (!method.isAnnotationPresent(AuthenticationNotRequired.class)) {
                context.register(AuthenticationFilter.class);
            }
        }
    }

}