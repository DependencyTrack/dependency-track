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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

/**
 * WhitelistUrlFilter is a configurable Servlet Filter that can prevent access to
 * specific URLs. The filter will ignore access to all URLs that are not specifically
 * whitelisted. Ignored URLs result in a HTTP 404 response.
 *
 * The filter may be used when specific files or directories should not be accessible.
 * In the case of executable WARs, use of this filter is highly recommended since
 * executable WARs must meet the requirements of both JAR and WAR files, thus placing
 * compiled classes and their package structure inside the document webroot.
 *
 * Sample usage:
 * <pre>
 * &lt;filter&gt;
 *   &lt;filter-name&gt;WhitelistUrlFilter&lt;/filter-name&gt;
 *   &lt;filter-class&gt;alpine.filters.WhitelistUrlFilter&lt;/filter-class&gt;
 *   &lt;init-param&gt;
 *     &lt;param-name&gt;allowUrls&lt;/param-name&gt;
 *     &lt;param-value&gt;/images,/css&lt;/param-value&gt;
 *   &lt;/init-param&gt;
 * &lt;/filter&gt;
 *
 * &lt;filter-mapping&gt;
 *   &lt;filter-name&gt;WhitelistUrlFilter&lt;/filter-name&gt;
 *   &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
 * &lt;/filter-mapping&gt;
 *
 * </pre>
 *
 * Optionally, the forwardTo parameter can be specified to instruct the
 * WhitelistUrlFilter to forward the request to a URL of another Servlet,
 * JSP, or HTML file should the originally requested URL not be whitelisted.
 * This may be necessary in some Single Page Applications (SPA).
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public final class WhitelistUrlFilter implements Filter {

    private String[] allowUrls = {};
    private String[] forwardExcludes = {};
    private String forwardTo = null;

    /**
     * Initialize "allowUrls" parameter from web.xml.
     *
     * @param filterConfig A filter configuration object used by a servlet container
     *                     to pass information to a filter during initialization.
     */
    public void init(final FilterConfig filterConfig) {

        final String allowParam = filterConfig.getInitParameter("allowUrls");
        if (allowParam != null && !allowParam.isBlank()) {
            this.allowUrls = allowParam.split(",");
        }

        final String forwardExcludesParam = filterConfig.getInitParameter("forwardExcludes");
        if (forwardExcludesParam != null && !forwardExcludesParam.isBlank()) {
            this.forwardExcludes = forwardExcludesParam.split(",");
        }

        final String forwardToParam = filterConfig.getInitParameter("forwardTo");
        if (forwardToParam != null && !forwardToParam.isBlank()) {
            this.forwardTo = forwardToParam;
        }

    }

    /**
     * Check for allowed URLs being requested.
     *
     * @param request The request object.
     * @param response The response object.
     * @param chain Refers to the {@code FilterChain} object to pass control to the next {@code Filter}.
     * @throws IOException a IOException
     * @throws ServletException a ServletException
     */
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse res = (HttpServletResponse) response;
        try {
            // Canonicalize the URI
            final String requestUri = new URI(req.getRequestURI()).normalize().getPath();
            if (requestUri != null) {
                // If the canonicalized URI still contains the '..' sequence, a potentially malicious request
                // has been made. Respond with a 400. NOTE: Jetty/Embedded already has protections against this,
                // therefore, the following code should never be true. But in the event Jetty changes in the future,
                // this code is left here as an additional layer of defense.
                // See: https://www.eclipse.org/jetty/javadoc/jetty-9/org/eclipse/jetty/http/HttpComplianceSection.html#NO_AMBIGUOUS_PATH_PARAMETERS
                if (requestUri.contains("..")) {
                    res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    return;
                }
                boolean allowed = false;
                final String requestUrlExcludingContext = requestUri.substring(req.getContextPath().length());
                for (final String url: allowUrls) {
                    if (requestUrlExcludingContext.equals("/")) {
                        if (url.trim().equals("/") || (url.trim().equals("/index.jsp")) || (url.trim().equals("/index.html"))) {
                            allowed = true;
                        }
                    } else if (requestUrlExcludingContext.startsWith(url.trim())) {
                        allowed = true;
                    }
                }
                if (!allowed) {
                    if (forwardTo != null) {
                        for (final String url: allowUrls) {
                            if (forwardExcludes != null && Arrays.stream(forwardExcludes).anyMatch(url::equals)) {
                                break;
                            }
                            final int occurrence = requestUrlExcludingContext.indexOf(url);
                            if (occurrence > -1) {
                                final String queryString = (req.getQueryString() == null) ? "" : "?" + req.getQueryString();
                                final String resourceUrl = requestUrlExcludingContext.substring(occurrence) + queryString;
                                req.getRequestDispatcher(resourceUrl).forward(request, response);
                                return;
                            }
                        }
                        req.getRequestDispatcher(forwardTo).forward(request, response);
                    } else {
                        res.setStatus(HttpServletResponse.SC_NOT_FOUND);
                    }
                    return;
                }
            }
        } catch (URISyntaxException e) {
            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean isExcludedForwardPath(String url) {
        return Arrays.stream(forwardExcludes).anyMatch(url::equals);
    }


    /**
     * {@inheritDoc}
     */
    public void destroy() {
    }

}
