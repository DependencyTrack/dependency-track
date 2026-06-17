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
package org.dependencytrack.dex.engine.api;

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.common.pagination.SimplePageTokenEncoder;

import javax.sql.DataSource;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.StringJoiner;
import java.util.UUID;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;
import static java.util.Objects.requireNonNull;

public class DexEngineConfig {

    public static class BufferConfig {

        private Duration flushInterval = Duration.ofMillis(100);
        private int maxBatchSize = 100;

        private BufferConfig() {
        }

        /**
         * @return Interval at which the buffer content is flushed.
         */
        public Duration flushInterval() {
            return flushInterval;
        }

        public void setFlushInterval(Duration flushInterval) {
            this.flushInterval = flushInterval;
        }

        /**
         * @return Maximum batch size of items to flush at once.
         */
        public int maxBatchSize() {
            return maxBatchSize;
        }

        public void setMaxBatchSize(int maxBatchSize) {
            this.maxBatchSize = maxBatchSize;
        }

        @Override
        public String toString() {
            return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
                    .add("flushInterval=" + flushInterval)
                    .add("maxBatchSize=" + maxBatchSize)
                    .toString();
        }

    }

    public static class CacheConfig {

        private Duration evictAfterAccess = Duration.ofMinutes(5);
        private int maxSize = 1000;

        private CacheConfig() {
        }

        public Duration evictAfterAccess() {
            return evictAfterAccess;
        }

        public void setEvictAfterAccess(Duration evictAfterAccess) {
            this.evictAfterAccess = evictAfterAccess;
        }

        public int maxSize() {
            return maxSize;
        }

        public void setMaxSize(int maxSize) {
            this.maxSize = maxSize;
        }

        @Override
        public String toString() {
            return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
                    .add("evictAfterAccess=" + evictAfterAccess)
                    .add("maxSize=" + maxSize)
                    .toString();
        }

    }

    public static class LeaderElectionConfig {

        private boolean enabled = true;
        private Duration leaseDuration = Duration.ofSeconds(30);
        private Duration leaseCheckInterval = Duration.ofSeconds(15);

        private LeaderElectionConfig() {
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * @return The duration for which leadership leases are valid for.
         */
        public Duration leaseDuration() {
            return leaseDuration;
        }

        public void setLeaseDuration(Duration leaseDuration) {
            this.leaseDuration = leaseDuration;
        }

        /**
         * @return The interval at which leadership leases will be checked for.
         */
        public Duration leaseCheckInterval() {
            return leaseCheckInterval;
        }

        public void setLeaseCheckInterval(Duration leaseCheckInterval) {
            this.leaseCheckInterval = leaseCheckInterval;
        }

        @Override
        public String toString() {
            return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
                    .add("enabled=" + enabled)
                    .add("leaseDuration=" + leaseDuration)
                    .add("leaseCheckInterval=" + leaseCheckInterval)
                    .toString();
        }

    }

    public static class MaintenanceConfig {

        private Duration runRetentionDuration = Duration.ofDays(1);
        private int runDeletionBatchSize = 1000;
        private Duration workerInitialDelay = Duration.ofMinutes(1);
        private Duration workerInterval = Duration.ofMinutes(30);

        private MaintenanceConfig() {
        }

        /**
         * @return Duration to retain completed workflow runs for.
         */
        public Duration runRetentionDuration() {
            return runRetentionDuration;
        }

        public void setRunRetentionDuration(Duration runRetentionDuration) {
            this.runRetentionDuration = runRetentionDuration;
        }

        /**
         * @return The number of completed workflow runs to delete in a single execution.
         */
        public int runDeletionBatchSize() {
            return runDeletionBatchSize;
        }

        public void setRunDeletionBatchSize(int runDeletionBatchSize) {
            this.runDeletionBatchSize = runDeletionBatchSize;
        }

        /**
         * @return Initial delay before the maintenance worker first runs.
         */
        public Duration workerInitialDelay() {
            return workerInitialDelay;
        }

        public void setWorkerInitialDelay(Duration workerInitialDelay) {
            this.workerInitialDelay = workerInitialDelay;
        }

        /**
         * @return Interval at which the maintenance worker will run.
         */
        public Duration workerInterval() {
            return workerInterval;
        }

        public void setWorkerInterval(Duration workerInterval) {
            this.workerInterval = workerInterval;
        }

        @Override
        public String toString() {
            return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
                    .add("runRetentionDuration=" + runRetentionDuration)
                    .add("runDeletionBatchSize=" + runDeletionBatchSize)
                    .add("workerInitialDelay=" + workerInitialDelay)
                    .add("workerInterval=" + workerInterval)
                    .toString();
        }

    }

    public static class MetricsConfig {

        private MeterRegistry meterRegistry = new SimpleMeterRegistry();
        private boolean collectorEnabled = true;
        private Duration collectorInitialDelay = Duration.ofSeconds(15);
        private Duration collectorInterval = Duration.ofSeconds(30);

        private MetricsConfig() {
        }

        public MeterRegistry meterRegistry() {
            return meterRegistry;
        }

        public void setMeterRegistry(MeterRegistry meterRegistry) {
            this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
        }

        public boolean isCollectorEnabled() {
            return collectorEnabled;
        }

        public void setCollectorEnabled(boolean collectorEnabled) {
            this.collectorEnabled = collectorEnabled;
        }

        public Duration collectorInitialDelay() {
            return collectorInitialDelay;
        }

        public void setCollectorInitialDelay(Duration collectorInitialDelay) {
            this.collectorInitialDelay = requireNonNull(collectorInitialDelay, "collectorInitialDelay must not be null");
        }

        public Duration collectorInterval() {
            return collectorInterval;
        }

        public void setCollectorInterval(Duration collectorInterval) {
            this.collectorInterval = requireNonNull(collectorInterval, "collectorInterval must not be null");
        }

        @Override
        public String toString() {
            return new StringJoiner(", ", MetricsConfig.class.getSimpleName() + "[", "]")
                    .add("meterRegistry=" + meterRegistry)
                    .add("collectorEnabled=" + collectorEnabled)
                    .add("collectorInitialDelay=" + collectorInitialDelay)
                    .add("collectorInterval=" + collectorInterval)
                    .toString();
        }

    }

    public static class TaskSchedulerConfig {

        private Duration pollInterval = Duration.ofMillis(100);
        private IntervalFunction pollBackoffFunction = ofExponentialRandomBackoff(100L, 2.0, 0.3, 3000L);

        private TaskSchedulerConfig() {
        }

        public Duration pollInterval() {
            return pollInterval;
        }

        public void setPollInterval(Duration pollInterval) {
            this.pollInterval = pollInterval;
        }

        public IntervalFunction pollBackoffFunction() {
            return pollBackoffFunction;
        }

        public void setPollBackoffFunction(IntervalFunction pollBackoffFunction) {
            this.pollBackoffFunction = pollBackoffFunction;
        }

        @Override
        public String toString() {
            return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
                    .add("pollInterval=" + pollInterval)
                    .add("pollBackoffFunction=" + pollBackoffFunction)
                    .toString();
        }

    }

    private final String instanceId;
    private final DataSource dataSource;
    private final LeaderElectionConfig leaderElectionConfig = new LeaderElectionConfig();
    private final CacheConfig runHistoryCacheConfig = new CacheConfig();
    private final BufferConfig externalEventBufferConfig = new BufferConfig();
    private final BufferConfig taskEventsBufferConfig = new BufferConfig();
    private final BufferConfig activityTaskHeartbeatBufferConfig = new BufferConfig();
    private final MaintenanceConfig maintenanceConfig = new MaintenanceConfig();
    private final MetricsConfig metricsConfig = new MetricsConfig();
    private final TaskSchedulerConfig workflowTaskSchedulerConfig = new TaskSchedulerConfig();
    private final TaskSchedulerConfig activityTaskSchedulerConfig = new TaskSchedulerConfig();

    private PageTokenEncoder pageTokenEncoder = new SimplePageTokenEncoder();

    public DexEngineConfig(DataSource dataSource) {
        this.instanceId = generateInstanceId();
        this.dataSource = requireNonNull(dataSource, "dataSource must not be null");
    }

    /**
     * @return ID that uniquely identifies this instance of the engine.
     */
    public String instanceId() {
        return instanceId;
    }

    /**
     * @return {@link DataSource} to use for persistence.
     */
    public DataSource dataSource() {
        return dataSource;
    }

    public LeaderElectionConfig leaderElection() {
        return leaderElectionConfig;
    }

    public CacheConfig runHistoryCache() {
        return runHistoryCacheConfig;
    }

    /**
     * @return Config for the buffer of external events.
     */
    public BufferConfig externalEventBuffer() {
        return externalEventBufferConfig;
    }

    /**
     * @return Config for the buffer of task events.
     */
    public BufferConfig taskEventBuffer() {
        return taskEventsBufferConfig;
    }

    public BufferConfig activityTaskHeartbeatBuffer() {
        return activityTaskHeartbeatBufferConfig;
    }

    /**
     * @return Maintenance config.
     */
    public MaintenanceConfig maintenance() {
        return maintenanceConfig;
    }

    /**
     * @return Metrics config.
     */
    public MetricsConfig metrics() {
        return metricsConfig;
    }

    public TaskSchedulerConfig workflowTaskScheduler() {
        return workflowTaskSchedulerConfig;
    }

    public TaskSchedulerConfig activityTaskScheduler() {
        return activityTaskSchedulerConfig;
    }

    public PageTokenEncoder pageTokenEncoder() {
        return pageTokenEncoder;
    }

    public void setPageTokenEncoder(PageTokenEncoder pageTokenEncoder) {
        this.pageTokenEncoder = requireNonNull(pageTokenEncoder, "pageTokenEncoder must not be null");
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
                .add("instanceId='" + instanceId + "'")
                .add("dataSource=" + dataSource)
                .add("leaderElectionConfig=" + leaderElectionConfig)
                .add("runHistoryCacheConfig=" + runHistoryCacheConfig)
                .add("externalEventBufferConfig=" + externalEventBufferConfig)
                .add("taskEventsBufferConfig=" + taskEventsBufferConfig)
                .add("activityTaskHeartbeatBufferConfig=" + activityTaskHeartbeatBufferConfig)
                .add("maintenanceConfig=" + maintenanceConfig)
                .add("metricsConfig=" + metricsConfig)
                .add("workflowTaskSchedulerConfig=" + workflowTaskSchedulerConfig)
                .add("activityTaskSchedulerConfig=" + activityTaskSchedulerConfig)
                .add("pageTokenEncoder=" + pageTokenEncoder)
                .toString();
    }

    private static String generateInstanceId() {
        final String hostName;
        try {
            hostName = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            throw new UncheckedIOException(e);
        }

        return "%s-%s".formatted(hostName, UUID.randomUUID().toString().substring(0, 8));
    }

}
