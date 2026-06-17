/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.server.filters;

import org.slf4j.MDC;

import jakarta.annotation.Priority;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

@Provider
@Priority(1)
public class RequestIdFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Pattern REQUEST_ID_PATTERN = Pattern.compile("^[A-Za-z0-9._\\-=+]{16,192}$");

    @Override
    public void filter(final ContainerRequestContext requestContext) throws IOException {
        String requestId = requestContext.getHeaderString("X-Request-Id");
        if (requestId == null || !REQUEST_ID_PATTERN.matcher(requestId).matches()) {
            requestId = UUID.randomUUID().toString();
        }

        requestContext.setProperty("requestId", requestId);
        MDC.put("requestId", requestId);
    }

    @Override
    public void filter(final ContainerRequestContext requestContext, final ContainerResponseContext responseContext) throws IOException {
        if (requestContext.getProperty("requestId") instanceof final String requestId) {
            responseContext.getHeaders().putSingle("X-Request-Id", requestId);
        }

        MDC.remove("requestId");
    }

}
