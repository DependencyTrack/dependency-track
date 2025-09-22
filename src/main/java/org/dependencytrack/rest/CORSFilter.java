/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * (Replace the above header block with the project's exact license/header block
 * copied from another source file in this repository if one exists. Many projects
 * require an exact header; copying that exactly avoids Checkstyle header violations.)
 */

package org.dependencytrack.rest;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;

/**
 * Adds permissive CORS headers to responses for development/testing.
 *
 * <p>Note: For production, restrict allowed origins instead of using "*".</p>
 */
@Provider
public final class CORSFilter implements ContainerResponseFilter {

    /**
     * Add CORS headers to every response.
     *
     * @param requestContext  the request context
     * @param responseContext the response context
     * @throws IOException when an I/O error occurs
     */
    @Override
    public void filter(final ContainerRequestContext requestContext,
                       final ContainerResponseContext responseContext) throws IOException {
        responseContext.getHeaders().add("Access-Control-Allow-Origin", "*");
        responseContext.getHeaders().add(
                "Access-Control-Allow-Headers",
                "origin, content-type, accept, authorization");
        responseContext.getHeaders().add("Access-Control-Allow-Credentials", "true");
        responseContext.getHeaders().add(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, DELETE, OPTIONS, HEAD");
    }
}
