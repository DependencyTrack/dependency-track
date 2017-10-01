/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import org.owasp.dependencytrack.event.IndexEvent;
import org.owasp.dependencytrack.search.IndexManagerFactory;
import org.owasp.dependencytrack.search.ObjectIndexer;

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
    public void inform(Event e) {

        if (e instanceof IndexEvent) {
            final IndexEvent event = (IndexEvent) e;
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
                LOGGER.info("Starting reindex task");
                //todo
                LOGGER.info("Reindexing complete");
            }
        }
    }
}
