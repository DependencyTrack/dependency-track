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
import org.owasp.dependencytrack.ConfigItem;
import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.HttpHeaders;

@Priority(Priorities.HEADER_DECORATOR)
public class HeaderFilter implements ContainerResponseFilter {

    private String appName;
    private String appVersion;

    private void init() {
        if (appName == null) {
            appName = Config.getInstance().getProperty(ConfigItem.APPLICATION_NAME);
        }
        if (appVersion == null) {
            appVersion = Config.getInstance().getProperty(ConfigItem.APPLICATION_VERSION);
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        init();
        responseContext.getHeaders().add("X-Powered-By", appName + " v" + appVersion);
        responseContext.getHeaders().add(HttpHeaders.CACHE_CONTROL, "private, max-age=0, must-revalidate, no-cache");

        // CORS Headers
        responseContext.getHeaders().add("Access-Control-Allow-Methods", "GET POST PUT DELETE");
        responseContext.getHeaders().add("Access-Control-Allow-Origin", "*");
        responseContext.getHeaders().add("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Api-Key, *");
        responseContext.getHeaders().add("Access-Control-Request-Headers", "Origin, Content-Type, Authorization, X-Api-Key, *");
    }

}