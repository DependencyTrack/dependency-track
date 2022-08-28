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

import javax.jdo.JDOHelper;
import javax.jdo.spi.PersistenceCapable;

/**
 * @since 4.6.0
 */
public final class PersistenceUtil {

    private PersistenceUtil() {
    }

    /**
     * Require that the given {@link PersistenceCapable} object is not attached to a {@link javax.jdo.PersistenceManager}.
     * <p>
     * Passing around attached instances of persistence capable objects can have unintended side effects that affect
     * performance (e.g. by loading fields from the datastore when calling getters),
     * or stability (e.g. when sharing attached objects across threads).
     * <p>
     * This method can and should be used in cases where an attached object is explicitly NOT expected.
     *
     * @param object The {@link PersistenceCapable} object to check
     */
    public static void requireDetached(final Object object) {
        if (JDOHelper.isPersistent(object) || JDOHelper.isTransactional(object)) {
            throw new IllegalArgumentException("The object is still attached to a PersistenceManager, which can cause unintended side-effects");
        }
    }

}
