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
package org.dependencytrack.persistence.listener;

import org.dependencytrack.persistence.QueryManager;

import javax.jdo.JDOHelper;
import javax.jdo.listener.DeleteLifecycleListener;
import javax.jdo.listener.InstanceLifecycleEvent;
import javax.jdo.listener.InstanceLifecycleListener;
import javax.jdo.listener.StoreLifecycleListener;

import static org.dependencytrack.util.PersistenceUtil.evictFromL2Cache;

/**
 * An {@link InstanceLifecycleListener} that evicts objects from the L2 cache upon modification or deletion.
 * <p>
 * It should be used in contexts where L2 caching is disabled (via {@link QueryManager#withL2CacheDisabled()}),
 * but L2 caching is not disabled globally. The cache is not updated when it's disabled (duh), potentially
 * causing areas of the application that still use it to operate on stale data.
 *
 * @since 4.11.0
 */
public class L2CacheEvictingInstanceLifecycleListener implements DeleteLifecycleListener, StoreLifecycleListener {

    private final QueryManager qm;

    public L2CacheEvictingInstanceLifecycleListener(final QueryManager qm) {
        this.qm = qm;
    }

    @Override
    public void preDelete(final InstanceLifecycleEvent event) {
    }

    @Override
    public void postDelete(final InstanceLifecycleEvent event) {
        evictFromL2Cache(qm, event.getPersistentInstance());
    }

    @Override
    public void preStore(final InstanceLifecycleEvent event) {
    }

    @Override
    public void postStore(final InstanceLifecycleEvent event) {
        final Object instance = event.getPersistentInstance();
        if (JDOHelper.isDirty(instance)) {
            evictFromL2Cache(qm, instance);
        }
    }

}
