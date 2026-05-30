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

import alpine.common.validation.RegexSequence;
import alpine.persistence.OrderDirection;
import alpine.persistence.Pagination;
import alpine.resources.AlpineRequest;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.ext.Provider;
import org.glassfish.jersey.server.ContainerRequest;

import java.security.Principal;
import java.util.Set;

@Provider
@Priority(Priorities.USER)
public class ApiFilter implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (requestContext instanceof ContainerRequest) {
            final ContainerRequest request = (ContainerRequest) requestContext;

            final MultivaluedMap<String, String> queryParams = request.getUriInfo().getQueryParameters();
            final String offset = multiParam(queryParams, "offset");
            final String page = multiParam(queryParams, "page", "pageNumber");
            final String size = multiParam(queryParams, "size", "pageSize", "limit");
            final String filter = multiParam(queryParams, "filter", "searchText");
            final String sort = multiParam(queryParams, "sort", "sortOrder");
            final OrderDirection orderDirection;
            String orderBy = multiParam(queryParams, "orderBy", "sortName");

            if (orderBy == null || orderBy.isBlank() || !RegexSequence.Pattern.STRING_IDENTIFIER.matcher(orderBy).matches()) {
                orderBy = null;
            }

            if ("asc".equalsIgnoreCase(sort)) {
                orderDirection = OrderDirection.ASCENDING;
            } else if ("desc".equalsIgnoreCase(sort)) {
                orderDirection = OrderDirection.DESCENDING;
            } else {
                orderDirection = OrderDirection.UNSPECIFIED;
            }

            final Pagination pagination;
            if (offset != null && !offset.isBlank()) {
                pagination = new Pagination(Pagination.Strategy.OFFSET, offset, size);
            } else if (page != null && !page.isBlank() && size != null && !size.isBlank()) {
                pagination = new Pagination(Pagination.Strategy.PAGES, page, size);
            } else {
                pagination = new Pagination(Pagination.Strategy.OFFSET, 0, 100); // Always paginate queries from resources
            }
            final AlpineRequest alpineRequest = new AlpineRequest(
                    getPrincipal(requestContext), pagination, filter, orderBy, orderDirection, getEffectivePermissions(requestContext));
            requestContext.setProperty("AlpineRequest", alpineRequest);
        }
    }

    /**
     * Provides a facility to retrieve a param by more than one name. Different libraries
     * and frameworks, expect (in some cases) different names for the same param.
     * @param queryParams the parameters from the querystring
     * @param params an array of one or more param names
     * @return the value of the param, or null if not found
     */
    private String multiParam(final MultivaluedMap<String, String> queryParams, final String... params) {
        for (final String param: params) {
            final String value = queryParams.getFirst(param);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    /**
     * Returns the principal for who initiated the request.
     * @return a Principal object
     * @see alpine.model.ApiKey
     * @see alpine.model.LdapUser
     */
    private Principal getPrincipal(ContainerRequestContext requestContext) {
        final Object principal = requestContext.getProperty("Principal");
        if (principal != null) {
            return (Principal) principal;
        } else {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private Set<String> getEffectivePermissions(final ContainerRequestContext requestContext) {
        return (Set<String>) requestContext.getProperty(AuthorizationFilter.EFFECTIVE_PERMISSIONS_PROPERTY);
    }

}
