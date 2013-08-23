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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */

package org.owasp.dependencytrack.controller.token;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TokenHandlerInterceptor extends HandlerInterceptorAdapter {

    /**
     * Intercepts an incoming requests, determines if method was POST and enforces token policy.
     * @param request The HttpServletRequest to intercept
     * @param response The HttpServletResponse
     * @param handler not-used but required for interface definition
     * @return a Boolean indicating if the request should be further processed.
     * @throws Exception Required by interface
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if ("POST".equalsIgnoreCase(request.getMethod())) {
            if (!TokenManager.isTokenValid(request)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Incorrect token value");
                return false;
            }
        }
        return true;
    }
}
