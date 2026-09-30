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

import alpine.model.auth.Principal;
import org.jspecify.annotations.Nullable;

public class AlpineRequest {

    private @Nullable Principal principal;
    private Pagination pagination;
    private String filter;
    private String orderBy;
    private OrderDirection orderDirection;
    private boolean portfolioAccessControlEnabled;

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
    public AlpineRequest(final @Nullable Principal principal, final Pagination pagination, final String filter,
                         final String orderBy, final OrderDirection orderDirection) {
        this(principal, pagination, filter, orderBy, orderDirection, /* portfolioAccessControlEnabled */ false);
    }

    /**
     * Constructs a new AlpineRequest.
     * @param principal a Principal, or null
     * @param pagination a Pagination request, or null
     * @param filter a String filter, or null
     * @param orderBy the field to order by
     * @param orderDirection the sorting direction
     * @param portfolioAccessControlEnabled whether portfolio access control is enabled
     * @since 5.2.0
     */
    public AlpineRequest(final @Nullable Principal principal, final Pagination pagination, final String filter,
                         final String orderBy, final OrderDirection orderDirection,
                         final boolean portfolioAccessControlEnabled) {
        this.principal = principal;
        this.pagination = pagination;
        this.filter = filter;
        this.orderBy = orderBy;
        this.orderDirection = orderDirection;
        this.portfolioAccessControlEnabled = portfolioAccessControlEnabled;
    }

    public @Nullable Principal getPrincipal() {
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
     * Whether portfolio access control was enabled when the request was authenticated.
     * This is deployment policy rather than an attribute of the principal, which is why
     * it belongs to the request.
     * @return true if portfolio access control is enabled
     * @since 5.2.0
     */
    public boolean isPortfolioAccessControlEnabled() {
        return portfolioAccessControlEnabled;
    }

}
