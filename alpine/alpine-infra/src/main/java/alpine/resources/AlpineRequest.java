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
package alpine.resources;

import alpine.persistence.OrderDirection;
import alpine.persistence.Pagination;

import java.security.Principal;
import java.util.Collections;
import java.util.Set;

public class AlpineRequest {

    private Principal principal;
    private Pagination pagination;
    private String filter;
    private String orderBy;
    private OrderDirection orderDirection;
    private Set<String> effectivePermissions;

    /**
     * Default constructor
     */
    public AlpineRequest() { }

    /**
     * Constructs a new QueryManager with the following:
     * @param principal a Principal, or null
     * @param pagination a Pagination request, or null
     * @param filter a String filter, or null
     * @param orderBy the field to order by
     * @param orderDirection the sorting direction
     */
    public AlpineRequest(final Principal principal, final Pagination pagination, final String filter,
                         final String orderBy, final OrderDirection orderDirection) {
        this.principal = principal;
        this.pagination = pagination;
        this.filter = filter;
        this.orderBy = orderBy;
        this.orderDirection = orderDirection;
    }

    /**
     * @since 3.2.0
     */
    public AlpineRequest(
            final Principal principal,
            final Pagination pagination,
            final String filter,
            final String orderBy,
            final OrderDirection orderDirection,
            final Set<String> effectivePermissions) {
        this.principal = principal;
        this.pagination = pagination;
        this.filter = filter;
        this.orderBy = orderBy;
        this.orderDirection = orderDirection;
        this.effectivePermissions = effectivePermissions;
    }

    public Principal getPrincipal() {
        return principal;
    }

    public Pagination getPagination() {
        return pagination;
    }

    public String getFilter() {
        return filter;
    }

    public String getOrderBy() {
        return orderBy;
    }

    public OrderDirection getOrderDirection() {
        return orderDirection;
    }

    /**
     * @since 3.2.0
     */
    public Set<String> getEffectivePermissions() {
        return effectivePermissions == null
                ? Collections.emptySet()
                : effectivePermissions;
    }

}
