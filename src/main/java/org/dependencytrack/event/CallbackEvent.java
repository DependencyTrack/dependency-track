package org.dependencytrack.event;

import alpine.event.framework.Event;

import java.util.Objects;

/**
 * Defines an {@link Event} that can be used to execute arbitrary callbacks.
 *
 * @since 4.6.0
 */
public class CallbackEvent implements Event {

    private final Runnable callback;

    public CallbackEvent(final Runnable callback) {
        this.callback = Objects.requireNonNull(callback, "Callback must not be null");
    }

    public Runnable getCallback() {
        return callback;
    }

}
