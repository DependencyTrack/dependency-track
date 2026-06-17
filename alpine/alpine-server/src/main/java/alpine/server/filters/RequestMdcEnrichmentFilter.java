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
package alpine.server.filters;

import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ExtendedUriInfo;
import org.glassfish.jersey.uri.UriTemplate;
import org.slf4j.MDC;

import jakarta.annotation.Priority;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.StringJoiner;
import java.util.regex.Pattern;

/**
 * @since 3.2.0
 */
@Provider
@Priority(2)
public class RequestMdcEnrichmentFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Pattern TRIM_SLASHES_PATTERN = Pattern.compile("//+");

    @Override
    public void filter(final ContainerRequestContext requestContext) throws IOException {
        MDC.put("requestMethod", requestContext.getMethod());
        MDC.put("requestUri", getRequestUri(requestContext));
    }

    @Override
    public void filter(final ContainerRequestContext requestContext, final ContainerResponseContext responseContext) throws IOException {
        MDC.remove("requestMethod");
        MDC.remove("requestUri");
    }

    private String getRequestUri(final ContainerRequestContext requestContext) {
        if (!(requestContext instanceof final ContainerRequest containerRequest)) {
            throw new IllegalStateException();
        }

        final ExtendedUriInfo uriInfo = containerRequest.getUriInfo();
        if (uriInfo.getMatchedTemplates().isEmpty()) {
            return null;
        }

        final var pathJoiner = new StringJoiner("/");
        for (final UriTemplate uriTemplate : uriInfo.getMatchedTemplates().reversed()) {
            pathJoiner.add(uriTemplate.getTemplate());
        }

        return TRIM_SLASHES_PATTERN.matcher(pathJoiner.toString()).replaceAll("/");
    }

}
