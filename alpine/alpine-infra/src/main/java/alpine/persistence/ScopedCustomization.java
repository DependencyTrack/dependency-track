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

import org.datanucleus.api.jdo.JDOPersistenceManager;

import javax.jdo.PersistenceManager;
import java.util.ArrayDeque;
import java.util.Deque;

public class ScopedCustomization implements AutoCloseable {

    private final JDOPersistenceManager pm;
    private final Deque<Runnable> cleanUpItems = new ArrayDeque<>();

    public ScopedCustomization(final PersistenceManager pm) {
        if (pm instanceof final JDOPersistenceManager jdoPm) {
            this.pm = jdoPm;
        } else {
            throw new IllegalArgumentException("Unsupported PersistenceManager type: %s"
                    .formatted(pm.getClass().getName()));
        }
    }

    public ScopedCustomization withDetachmentOptions(final int detachmentOptions) {
        final var originalOptions = pm.getFetchPlan().getDetachmentOptions();
        cleanUpItems.add(() -> pm.getFetchPlan().setDetachmentOptions(originalOptions));
        pm.getFetchPlan().setDetachmentOptions(detachmentOptions);
        return this;
    }

    public ScopedCustomization withFetchGroup(final String fetchGroup) {
        final var originalFetchGroups = pm.getFetchPlan().getGroups();
        cleanUpItems.add(() -> pm.getFetchPlan().setGroups(originalFetchGroups));
        pm.getFetchPlan().setGroups(fetchGroup);
        return this;
    }

    public ScopedCustomization withProperty(final String name, final String value) {
        final Object originalValue = pm.getExecutionContext().getProperty(name);
        cleanUpItems.add(() -> pm.setProperty(name, originalValue));
        pm.setProperty(name, value);
        return this;
    }

    @Override
    public void close() {
        cleanUpItems.forEach(Runnable::run);
    }

}
