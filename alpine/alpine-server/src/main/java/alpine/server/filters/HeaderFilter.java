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

import alpine.config.AlpineConfigKeys;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.HttpHeaders;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

/**
 * Adds Powered-By and cache-control headers.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
@Priority(Priorities.HEADER_DECORATOR)
public class HeaderFilter implements ContainerResponseFilter {

    private static final String APP_NAME;
    private static final String APP_VERSION;
    private static final boolean CORS_ENABLED;
    private static final String CORS_ALLOW_ORIGIN;
    private static final String CORS_ALLOW_METHODS;
    private static final String CORS_ALLOW_HEADERS;
    private static final String CORS_EXPOSE_HEADERS;
    private static final boolean CORS_ALLOW_CREDENTIALS;
    private static final int CORS_MAX_AGE;

    static {
        final Config config = ConfigProvider.getConfig();
        APP_NAME = config.getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_NAME, String.class);
        APP_VERSION = config.getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_VERSION, String.class);
        CORS_ENABLED = config.getValue(AlpineConfigKeys.CORS_ENABLED, Boolean.class);
        CORS_ALLOW_ORIGIN = config.getOptionalValue(AlpineConfigKeys.CORS_ALLOW_ORIGIN, String.class).orElse(null);
        CORS_ALLOW_METHODS = config.getOptionalValue(AlpineConfigKeys.CORS_ALLOW_METHODS, String.class).orElse(null);
        CORS_ALLOW_HEADERS = config.getOptionalValue(AlpineConfigKeys.CORS_ALLOW_HEADERS, String.class).orElse(null);
        CORS_EXPOSE_HEADERS = config.getOptionalValue(AlpineConfigKeys.CORS_EXPOSE_HEADERS, String.class).orElse(null);
        CORS_ALLOW_CREDENTIALS = config.getValue(AlpineConfigKeys.CORS_ALLOW_CREDENTIALS, Boolean.class);
        CORS_MAX_AGE = config.getValue(AlpineConfigKeys.CORS_MAX_AGE, Integer.class);
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        responseContext.getHeaders().add("X-Powered-By", APP_NAME + " v" + APP_VERSION);
        responseContext.getHeaders().add(HttpHeaders.CACHE_CONTROL, "private, max-age=0, must-revalidate, no-cache");

        if (CORS_ENABLED) {
            if (CORS_ALLOW_ORIGIN != null && !CORS_ALLOW_ORIGIN.isBlank()) {
                responseContext.getHeaders().add("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN);
            }
            if (CORS_ALLOW_METHODS != null && !CORS_ALLOW_METHODS.isBlank()) {
                responseContext.getHeaders().add("Access-Control-Allow-Methods", CORS_ALLOW_METHODS);
            }
            if (CORS_ALLOW_HEADERS != null && !CORS_ALLOW_HEADERS.isBlank()) {
                responseContext.getHeaders().add("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS);
            }
            if (CORS_EXPOSE_HEADERS != null && !CORS_EXPOSE_HEADERS.isBlank()) {
                responseContext.getHeaders().add("Access-Control-Expose-Headers", CORS_EXPOSE_HEADERS);
            }
            if (CORS_ALLOW_CREDENTIALS) {
                responseContext.getHeaders().add("Access-Control-Allow-Credentials", "true");
            }
            if (CORS_MAX_AGE != 0) {
                responseContext.getHeaders().add("Access-Control-Max-Age", CORS_MAX_AGE);
            }
        }
    }
}
