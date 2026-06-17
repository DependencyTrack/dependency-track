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
package org.dependencytrack.filters;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.ext.Provider;

import java.lang.reflect.Method;

/**
 * @since 5.0.0
 */
@Provider
@Priority(Priorities.HEADER_DECORATOR)
public final class DeprecationResponseFilter implements ContainerResponseFilter {

    private final ResourceInfo resourceInfo;

    public DeprecationResponseFilter(@Context ResourceInfo resourceInfo) {
        this.resourceInfo = resourceInfo;
    }

    @Override
    public void filter(
            ContainerRequestContext requestContext,
            ContainerResponseContext responseContext) {
        final Method method = resourceInfo.getResourceMethod();
        if (method == null) {
            return;
        }

        if (!method.isAnnotationPresent(Deprecated.class)
                && !method.getDeclaringClass().isAnnotationPresent(Deprecated.class)) {
            return;
        }

        responseContext.getHeaders().putSingle("X-API-Deprecated", "true");
    }

}
