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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import io.micrometer.core.instrument.Timer;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.search.IndexManager;
import org.dependencytrack.search.IndexManagerFactory;
import org.dependencytrack.search.ObjectIndexer;

/**
 * Subscriber task that performs an action on an Index.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class IndexTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(IndexTask.class);

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    public void inform(final Event e) {

        if (e instanceof IndexEvent) {
            final IndexEvent event = (IndexEvent) e;

            if (IndexEvent.Action.CHECK == event.getAction()) {
                IndexManager.checkIndexesConsistency();
                return;
            }

            final ObjectIndexer indexManager = IndexManagerFactory.getIndexManager(event);

            if (IndexEvent.Action.CREATE == event.getAction()) {
                indexManager.add((event).getObject());
            } else if (IndexEvent.Action.UPDATE == event.getAction()) {
                indexManager.remove((event).getObject());
                indexManager.add((event).getObject());
            } else if (IndexEvent.Action.DELETE == event.getAction()) {
                indexManager.remove((event).getObject());
            } else if (IndexEvent.Action.COMMIT == event.getAction()) {
                indexManager.commit();
            } else if (IndexEvent.Action.REINDEX == event.getAction()) {
                Timer timer = Timer.builder("lucene_index_rebuild")
                        .description("Lucene index rebuild")
                        .tags("type", event.getIndexableClass().getName().toLowerCase())
                        .register(Metrics.getRegistry());
                Timer.Sample recording = Timer.start();
                indexManager.reindex();
                recording.stop(timer);
            }
        }
    }
}
