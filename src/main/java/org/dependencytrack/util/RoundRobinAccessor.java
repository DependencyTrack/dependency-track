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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A helper class for accessing elements in a {@link List} in a thread safe round-robin fashion.
 *
 * @param <T> Type of the elements contained in the {@link List} to manage access to
 * @since 4.7.0
 */
public class RoundRobinAccessor<T> {

    private final List<T> list;
    private final AtomicInteger index;

    public RoundRobinAccessor(final List<T> list) {
        this(list, new AtomicInteger());
    }

    RoundRobinAccessor(final List<T> list, final AtomicInteger index) {
        this.list = Collections.unmodifiableList(list);
        this.index = index;
    }

    public T get() {
        // "& Integer.MAX_VALUE" resets the sign should x overflow.
        // https://engineering.atspotify.com/2015/08/underflow-bug/
        return list.get(index.getAndUpdate(x -> (x + 1) & Integer.MAX_VALUE) % list.size());
    }

}
