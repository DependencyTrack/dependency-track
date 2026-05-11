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
package org.dependencytrack.common.pagination;

import org.jspecify.annotations.Nullable;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.function.Function;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class PageIterator<T> implements Iterator<T> {

    private final Function<@Nullable String, Page<T>> pageFunction;
    private @Nullable String nextPageToken;
    private @Nullable Iterator<T> currentPageIterator;
    private boolean hasCalledNext = false;

    public PageIterator(Function<@Nullable String, Page<T>> pageFunction) {
        this.pageFunction = requireNonNull(pageFunction, "pageFunction must not be null");
    }

    public static <T> Stream<T> stream(Function<@Nullable String, Page<T>> pageFunction) {
        final Iterable<T> iterable = () -> new PageIterator<>(pageFunction);
        return StreamSupport.stream(iterable.spliterator(), false);
    }

    @Override
    public boolean hasNext() {
        maybeLoadNextPage();
        return currentPageIterator != null
                && currentPageIterator.hasNext();
    }

    @Override
    public T next() {
        maybeLoadNextPage();
        if (currentPageIterator == null || !currentPageIterator.hasNext()) {
            throw new NoSuchElementException();
        }

        return currentPageIterator.next();
    }

    private void maybeLoadNextPage() {
        final boolean shouldLoadInitialPage = !hasCalledNext;
        final boolean shouldLoadNextPage = currentPageIterator != null
                && !currentPageIterator.hasNext()
                && nextPageToken != null;

        if (shouldLoadInitialPage || shouldLoadNextPage) {
            final Page<T> page = pageFunction.apply(nextPageToken);
            currentPageIterator = page.items().iterator();
            nextPageToken = page.nextPageToken();
            hasCalledNext = true;
        }
    }

}
