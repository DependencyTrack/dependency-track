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
package org.dependencytrack.common;

import alpine.logging.Logger;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import java.io.IOException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Manages a pool of Apache HttpClient objects.
 */
public class HttpClientPool {

    private static final Logger LOGGER = Logger.getLogger(HttpClientPool.class);



    // Watches for stale connections and evicts them.
    private static class IdleConnectionMonitor implements Runnable {
        // The manager to watch.
        private final PoolingHttpClientConnectionManager cm;
        // Use a BlockingQueue to stop everything.
        private final BlockingQueue<Stop> stopSignal = new ArrayBlockingQueue<>(1);

        IdleConnectionMonitor(PoolingHttpClientConnectionManager cm) {
            this.cm = cm;
        }


        // Pushed up the queue.
        private static class Stop {
            // The return queue.
            private final BlockingQueue<Stop> stop = new ArrayBlockingQueue<>(1);

            // Called by the process that is being told to stop.
            public void stopped() {
                // Push me back up the queue to indicate we are now stopped.
                stop.add(this);
            }

            // Called by the process requesting the stop.
            public void waitForStopped() throws InterruptedException {
                // Wait until the callee acknowledges that it has stopped.
                stop.take();
            }
        }

        public void shutdown() throws InterruptedException, IOException {
            LOGGER.info("Shutting down client pool");
            // Signal the stop to the thread.
            Stop stop = new Stop();
            stopSignal.add(stop);
            // Wait for the stop to complete.
            stop.waitForStopped();
            // Close the pool.
            HttpClientPool.getClient().close();
            // Close the connection manager.
            cm.close();
            LOGGER.info("Client pool shut down");
        }
    }
}