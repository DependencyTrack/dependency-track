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

    // Single-element enum to implement Singleton.
    private enum Singleton {
        Client;

        // The thread-safe client.
        private final CloseableHttpClient threadSafeClient;
        // The pool monitor.
        private final IdleConnectionMonitor monitor;

        // The constructor creates it - thus late
        Singleton() {
            final ManagedHttpClient pooledHttpClient = ManagedHttpClientFactory.newManagedHttpClient();
            threadSafeClient = pooledHttpClient.getHttpClient();
            PoolingHttpClientConnectionManager cm = pooledHttpClient.getConnectionManager();

            // Start up an eviction thread.
            monitor = new IdleConnectionMonitor(cm);
            // Start up the monitor.
            Thread monitorThread = new Thread(monitor);
            monitorThread.setDaemon(true);
            monitorThread.start();
        }

        public CloseableHttpClient get() {
            return threadSafeClient;
        }
    }

    public static CloseableHttpClient getClient() {
        // The thread safe client is held by the singleton.
        return Singleton.Client.get();
    }

    public static void shutdown() throws InterruptedException, IOException {
        // Shutdown the monitor.
        Singleton.Client.monitor.shutdown();
    }

    // Watches for stale connections and evicts them.
    private static class IdleConnectionMonitor implements Runnable {
        // The manager to watch.
        private final PoolingHttpClientConnectionManager cm;
        // Use a BlockingQueue to stop everything.
        private final BlockingQueue<Stop> stopSignal = new ArrayBlockingQueue<>(1);

        IdleConnectionMonitor(PoolingHttpClientConnectionManager cm) {
            this.cm = cm;
        }

        public void run() {
            try {
                // Holds the stop request that stopped the process.
                Stop stopRequest;
                // Every 5 seconds.
                while ((stopRequest = stopSignal.poll(5, TimeUnit.SECONDS)) == null) {
                    // Close expired connections
                    cm.closeExpiredConnections();
                    // Optionally, close connections that have been idle too long.
                    cm.closeIdleConnections(60, TimeUnit.SECONDS);
                    LOGGER.debug("Stats: " + cm.getTotalStats().toString());
                }
                // Acknowledge the stop request.
                stopRequest.stopped();
            } catch (InterruptedException ex) {
                // terminate
            }
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