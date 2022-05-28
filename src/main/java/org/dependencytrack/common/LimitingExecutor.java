package org.dependencytrack.common;

import alpine.common.logging.Logger;

import javax.annotation.Nullable;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.Semaphore;

/**
 * An {@link Executor} that ensures that only a limited amount of tasks
 * is being executed concurrently by a delegate {@link Executor}.
 * <p>
 * This is used to prevent scenarios where an {@link Executor} must be shut down
 * but still has multiple hundreds or thousands of tasks queued.
 *
 * @since 4.6.0
 */
public final class LimitingExecutor implements Executor {

    private static final Logger LOGGER = Logger.getLogger(LimitingExecutor.class);

    private final Semaphore semaphore;
    private final Executor delegateExecutor;

    /**
     * @param delegateExecutor The {@link Executor} to delegate tasks to
     * @param limit The limit of concurrent tasks
     */
    public LimitingExecutor(final Executor delegateExecutor, final int limit) {
        this.delegateExecutor = delegateExecutor;
        this.semaphore = new Semaphore(limit);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void execute(@Nullable final Runnable command) {
        Objects.requireNonNull(command);

        try {
            semaphore.acquire();
        } catch (InterruptedException e) {
            LOGGER.debug("Interrupted while waiting for permit to be acquired from semaphore", e);
            return;
        }

        delegateExecutor.execute(() -> {
            try {
                command.run();
            } finally {
                semaphore.release();
            }
        });
    }

}
