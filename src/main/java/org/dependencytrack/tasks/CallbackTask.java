package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.CallbackEvent;

/**
 * A {@link Subscriber} task that executes callbacks defined in {@link CallbackEvent}s.
 *
 * @since 4.6.0
 */
public class CallbackTask implements Subscriber {

    @Override
    public void inform(final Event e) {
        if (e instanceof CallbackEvent) {
            final var event = (CallbackEvent) e;
            event.getCallback().run();
        }
    }

}
