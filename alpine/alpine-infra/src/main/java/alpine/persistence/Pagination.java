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
package alpine.persistence;

/**
 * Defines pagination used during a request.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class Pagination {

    public enum Strategy {
        OFFSET,
        PAGES,
        NONE
    }

    private final Strategy strategy;
    private int offset;
    private int limit;

    /**
     * Creates a new Pagination object with the specified offset and limit, or page number
     * and size. If any parameters are null, a value of 0 will be used.
     * @param strategy the pagination strategy to use
     * @param o1 the offset or page number to use
     * @param o2 the number of results to limit a result-set to (aka, the size of the page)
     */
    public Pagination(final Strategy strategy, final int o1, final int o2) {
        this.strategy = strategy;
        calculateStrategy(strategy, o1, o2);
    }

    /**
     * Creates a new Pagination object with the specified offset and limit, or page number
     * and size. If any parameters are null, a value of 0 will be used.
     * @param strategy the pagination strategy to use
     * @param o1 the offset or page number to use
     * @param o2 the number of results to limit a result-set to (aka, the size of the page)
     */
    public Pagination(final Strategy strategy, final String o1, final String o2) {
        this.strategy = strategy;
        if (Strategy.OFFSET == strategy) {
            calculateStrategy(strategy, parseIntegerFromParam(o1, 0), parseIntegerFromParam(o2, 100));
        } else if (Strategy.PAGES == strategy) {
            calculateStrategy(strategy, parseIntegerFromParam(o1, 1), parseIntegerFromParam(o2, 100));
        }
    }

    /**
     * Determines the offset and limit based on pagination strategy.
     * @param strategy the pagination strategy to use
     * @param o1 the offset or page number to use
     * @param o2 the number of results to limit a result-set to (aka, the size of the page)
     */
    private void calculateStrategy(final Strategy strategy, final int o1, final int o2) {
        if (Strategy.OFFSET == strategy) {
            this.offset = o1;
            this.limit = o2;
        } else if (Strategy.PAGES == strategy) {
            this.offset = (o1 * o2) -  o2;
            this.limit = o2;
        }
    }

    /**
     * Returns the pagination strategy used.
     * @return the pagination strategy
     */
    public Strategy getStrategy() {
        return strategy;
    }

    /**
     * Returns the offset.
     * @return the offset
     */
    public int getOffset() {
        return offset;
    }

    /**
     * Returns the limit.
     * @return the limit
     */
    public int getLimit() {
        return limit;
    }

    /**
     * Returns if pagination is being used for this request. A page number and page size
     * greater than 0 will return true. If either of those are 0, method will return false.
     * @return if paginiation is used for this request
     */
    public boolean isPaginated() {
        return (Strategy.OFFSET == strategy || Strategy.PAGES == strategy) && limit > 0;
    }

    /**
     * Parses a parameter to an Integer, defaulting to 0 upon any errors encountered.
     * @param value the value to parse
     * @param defaultValue the default value to use
     * @return an Integer
     */
    private Integer parseIntegerFromParam(final String value, final int defaultValue) {
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException | NullPointerException e) {
            return defaultValue;
        }
    }

}
