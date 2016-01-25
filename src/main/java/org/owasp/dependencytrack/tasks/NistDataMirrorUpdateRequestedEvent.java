package org.owasp.dependencytrack.tasks;

import org.springframework.context.ApplicationEvent;

/**
 * Created by Jason Wraxall on 21/12/15.
 */
public class NistDataMirrorUpdateRequestedEvent extends ApplicationEvent {
    /**
     * Create a new ApplicationEvent.
     *
     * @param source the object on which the event initially occurred (never {@code null})
     */
    public NistDataMirrorUpdateRequestedEvent(Object source) {
        super(source);
    }
}
