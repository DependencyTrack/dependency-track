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
package org.dependencytrack;

import alpine.config.AlpineConfigKeys;
import alpine.server.AlpineServlet;
import alpine.server.filters.WhitelistUrlFilter;
import alpine.server.persistence.PersistenceManagerFactory;
import ch.qos.logback.classic.LoggerContext;
import io.github.mweirauch.micrometer.jvm.extras.ProcessMemoryMetrics;
import io.github.mweirauch.micrometer.jvm.extras.ProcessThreadMetrics;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.binder.jvm.ClassLoaderMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmInfoMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics;
import io.micrometer.core.instrument.binder.system.ProcessorMetrics;
import io.micrometer.core.instrument.binder.system.UptimeMetrics;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import jakarta.servlet.DispatcherType;
import org.dependencytrack.cache.CacheManagerBinder;
import org.dependencytrack.cache.CacheManagerInitializer;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.dependencytrack.dev.DevServices;
import org.dependencytrack.dex.DexEngineBinder;
import org.dependencytrack.dex.DexEngineInitializer;
import org.dependencytrack.filestorage.FileStorageBinder;
import org.dependencytrack.filestorage.FileStorageInitializer;
import org.dependencytrack.init.InitTaskExecutor;
import org.dependencytrack.init.InitTasksHealthCheck;
import org.dependencytrack.notification.DefaultNotificationPublisherInitializer;
import org.dependencytrack.notification.NotificationSubsystemInitializer;
import org.dependencytrack.observability.LoggingConfiguration;
import org.dependencytrack.observability.ManagementServer;
import org.dependencytrack.plugin.PluginInitializer;
import org.dependencytrack.plugin.PluginManagerBinder;
import org.dependencytrack.secret.SecretManagerBinder;
import org.dependencytrack.secret.SecretManagerInitializer;
import org.dependencytrack.tasks.TaskSchedulerInitializer;
import org.eclipse.jetty.compression.gzip.GzipCompression;
import org.eclipse.jetty.compression.server.CompressionHandler;
import org.eclipse.jetty.ee11.servlet.DefaultServlet;
import org.eclipse.jetty.ee11.servlet.FilterHolder;
import org.eclipse.jetty.ee11.servlet.ServletContextHandler;
import org.eclipse.jetty.ee11.servlet.ServletHandler;
import org.eclipse.jetty.ee11.servlet.ServletHolder;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.ForwardedRequestCustomizer;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.resource.ResourceFactory;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.net.URL;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import static org.glassfish.jersey.server.ServerProperties.BV_SEND_ERROR_IN_RESPONSE;
import static org.glassfish.jersey.server.ServerProperties.WADL_FEATURE_DISABLE;

public final class Application {

    private static final Logger LOGGER = LoggerFactory.getLogger(Application.class);

    public static void main(final String[] args) {
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();

        final Config config = ConfigProvider.getConfig();
        new LoggingConfiguration(config).apply((LoggerContext) LoggerFactory.getILoggerFactory());

        failOnLegacyFileSecretProperties(config);

        var contextPath = "/";
        var host = "0.0.0.0";
        var port = 8080;
        for (int i = 0; i < args.length - 1; i++) {
            switch (args[i]) {
                case "-context" -> contextPath = args[++i];
                case "-host" -> host = args[++i];
                case "-port" -> port = Integer.parseInt(args[++i]);
            }
        }

        // Start dev services (if enabled) before anything else.
        final var devServices = new DevServices();
        devServices.start();

        // Set up health check registry and init tasks health check.
        final var healthCheckRegistry = new HealthCheckRegistry();
        healthCheckRegistry.discoverChecks();
        final var initTasksHealthCheck = new InitTasksHealthCheck();
        healthCheckRegistry.addCheck(initTasksHealthCheck);

        // Set up metrics.
        final var prometheusMeterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        Metrics.addRegistry(prometheusMeterRegistry);
        configureMeterRegistry(config, Metrics.globalRegistry);

        // Start management server so health and metrics are available during init.
        final String managementHost = config
                .getOptionalValue(ConfigKeys.MANAGEMENT_HOST, String.class)
                .orElse("0.0.0.0");
        final int managementPort = config
                .getOptionalValue(ConfigKeys.MANAGEMENT_PORT, int.class)
                .orElse(9000);
        final var managementServer = new ManagementServer(
                managementHost,
                managementPort,
                healthCheckRegistry,
                prometheusMeterRegistry,
                config);
        try {
            managementServer.start();
        } catch (Exception e) {
            LOGGER.error("Failed to start management server", e);
            System.exit(-1);
        }

        // Execute init tasks.
        final var dataSourceRegistry = DataSourceRegistry.getInstance();
        if (config.getValue(ConfigKeys.INIT_TASKS_ENABLED, boolean.class)) {
            final String dataSourceName = config.getValue(ConfigKeys.INIT_TASKS_DATASOURCE_NAME, String.class);
            final var initTaskExecutor = new InitTaskExecutor(
                    config, dataSourceRegistry.get(dataSourceName),
                    initTasksHealthCheck);
            initTaskExecutor.execute();

            if (config.getValue(ConfigKeys.INIT_TASKS_DATASOURCE_CLOSE_AFTER_USE, boolean.class)) {
                dataSourceRegistry.close(dataSourceName);
            }
            if (config.getValue(ConfigKeys.INIT_AND_EXIT, boolean.class)) {
                LOGGER.info("Exiting because dt.init.and.exit is enabled");
                System.exit(0);
            }
        }
        initTasksHealthCheck.markInitialized();

        // Set up and start the main server.
        final var server = new Server();
        server.setStopAtShutdown(true);

        final var httpConfig = new HttpConfiguration();
        httpConfig.addCustomizer(new ForwardedRequestCustomizer());
        httpConfig.setSendServerVersion(false);

        // Enable legacy URI compliance to allow URL encoding in path segments.
        // Must additionally enable decoding of ambiguous URIs in the servlet handler
        // after server start (see below).
        httpConfig.setUriCompliance(UriCompliance.LEGACY);

        final var connector = new ServerConnector(server, new HttpConnectionFactory(httpConfig));
        connector.setHost(host);
        connector.setPort(port);
        server.setConnectors(new Connector[]{connector});

        final var context = new ServletContextHandler();
        context.setContextPath(contextPath);
        context.setErrorHandler((request, response, callback) -> {
            callback.succeeded();
            return true;
        });
        context.setInitParameter("org.eclipse.jetty.servlet.Default.dirAllowed", "false");

        final URL staticUrl = Application.class.getResource("/static");
        if (staticUrl != null) {
            try {
                context.setBaseResource(ResourceFactory.of(context).newResource(staticUrl.toURI()));
            } catch (Exception e) {
                LOGGER.error("Failed to set base resource", e);
                System.exit(-1);
            }
        }

        context.addEventListener(new CacheManagerInitializer());
        context.addEventListener(new FileStorageInitializer());
        context.addEventListener(new SecretManagerInitializer());
        context.addEventListener(new PersistenceManagerFactory());
        context.addEventListener(new PluginInitializer());
        context.addEventListener(new DefaultNotificationPublisherInitializer());
        context.addEventListener(
                new DexEngineInitializer(
                        config,
                        dataSourceRegistry,
                        Metrics.globalRegistry,
                        healthCheckRegistry));
        context.addEventListener(new TaskSchedulerInitializer(healthCheckRegistry));
        context.addEventListener(new NotificationSubsystemInitializer());

        final var whitelistFilter = new FilterHolder(WhitelistUrlFilter.class);
        whitelistFilter.setInitParameter("allowUrls", "/index.html,/api,/.well-known");
        whitelistFilter.setInitParameter("forwardTo", "/index.html");
        whitelistFilter.setInitParameter("forwardExcludes", "/api");
        context.addFilter(whitelistFilter, "/*", EnumSet.of(DispatcherType.REQUEST));

        final var apiV1Config = new ResourceConfig();
        apiV1Config.packages(
                "alpine.server.filters",
                "alpine.server.resources",
                "org.dependencytrack.filters",
                "org.dependencytrack.resources.v1");
        apiV1Config.register(CacheManagerBinder.class);
        apiV1Config.register(DexEngineBinder.class);
        apiV1Config.register(FileStorageBinder.class);
        apiV1Config.register(PluginManagerBinder.class);
        apiV1Config.register(SecretManagerBinder.class);
        apiV1Config.register(MultiPartFeature.class);
        apiV1Config.property(BV_SEND_ERROR_IN_RESPONSE, true);
        apiV1Config.property(WADL_FEATURE_DISABLE, true);

        final var apiV1Servlet = new ServletHolder("DependencyTrack", new AlpineServlet(apiV1Config));
        apiV1Servlet.setInitOrder(1);
        context.addServlet(apiV1Servlet, "/api/*");

        final var apiV2Servlet = new ServletHolder("REST-API-v2", new ServletContainer(
                new org.dependencytrack.resources.v2.ResourceConfig()));
        context.addServlet(apiV2Servlet, "/api/v2/*");
        context.addServlet(new ServletHolder("default", DefaultServlet.class), "/");

        final var gzipCompression = new GzipCompression();
        gzipCompression.setMinCompressSize(1024);
        final var compressionHandler = new CompressionHandler();
        compressionHandler.putCompression(gzipCompression);
        compressionHandler.setHandler(context);
        server.setHandler(compressionHandler);

        try {
            server.start();
        } catch (Exception e) {
            LOGGER.error("Failed to start server", e);
            System.exit(-1);
        }

        for (final var handler : server.getContainedBeans(ServletHandler.class)) {
            handler.setDecodeAmbiguousURIs(true);
        }

        try {
            server.join();
        } catch (InterruptedException e) {
            LOGGER.warn("Interrupted while waiting for server to stop");
        } finally {
            try {
                LOGGER.debug("Stopping management server");
                managementServer.close();
            } catch (Exception e) {
                LOGGER.warn("Failed to stop management server", e);
            }
            try {
                LOGGER.debug("Stopping dev services");
                devServices.close();
            } catch (Exception e) {
                LOGGER.warn("Failed to stop dev services", e);
            }
        }
    }

    private static final Set<String> LEGACY_FILE_SECRET_PROPERTIES = Set.of(
            "alpine.database.password.file",
            "alpine.http.proxy.password.file",
            "alpine.ldap.bind.password.file",
            "dt.database.password.file",
            "dt.http.proxy.password.file",
            "dt.ldap.bind.password.file");

    private static void failOnLegacyFileSecretProperties(Config config) {
        final var presentPropertyNames = new HashSet<String>();
        LEGACY_FILE_SECRET_PROPERTIES.forEach(name -> {
            if (config.getOptionalValue(name, String.class).isPresent()) {
                presentPropertyNames.add(name);
            }
        });
        if (presentPropertyNames.isEmpty()) {
            return;
        }

        throw new IllegalStateException("""
                Legacy file-secret properties are no longer supported: %s; \
                Replace each <key>.file=/path with <key>=${file::/path}\
                """.formatted(presentPropertyNames));
    }

    private static final Set<String> HISTOGRAM_METER_NAMES = Set.of(
            "dbscheduler_task_duration",
            "dt.dex.engine.activity.task.scheduling.latency",
            "dt.dex.engine.buffer.flush.batch.size",
            "dt.dex.engine.buffer.flush.latency",
            "dt.dex.engine.buffer.item.wait.latency",
            "dt.dex.engine.task.worker.poll.latency",
            "dt.dex.engine.task.worker.process.latency",
            "dt.dex.engine.task.worker.tasks.polled",
            "dt.dex.engine.workflow.task.scheduling.latency",
            "dt.notification.router.rule.filter.latency",
            "dt.notification.router.rule.query.latency",
            "dt.notifications.emit.latency",
            "dt.outbox.relay.cycle.latency",
            "dt.outbox.relay.poll.latency",
            "dt.outbox.relay.send.latency",
            "http.client.requests",
            "http.server.requests",
            "jdbi.query.latency",
            "vuln_policy_evaluation");

    private static void configureMeterRegistry(Config config, MeterRegistry meterRegistry) {
        final boolean metricsEnabled = config
                .getOptionalValue(ConfigKeys.METRICS_ENABLED, boolean.class)
                .orElse(false);
        if (!metricsEnabled) {
            return;
        }

        meterRegistry.config().meterFilter(new MeterFilter() {
            @Override
            public DistributionStatisticConfig configure(Meter.Id id, DistributionStatisticConfig config) {
                if (HISTOGRAM_METER_NAMES.contains(id.getName())) {
                    return DistributionStatisticConfig.builder()
                            .percentiles(/* none */) // Disable client-side calculation of percentiles.
                            .percentilesHistogram(true) // Publish histogram instead.
                            .build()
                            .merge(config);
                }

                return config;
            }
        });

        Gauge
                .builder("dt.info", () -> 1)
                .description("Metadata about the Dependency-Track application")
                .tag("version", config.getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_VERSION, String.class))
                .tag("built_at", config.getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_TIMESTAMP, String.class))
                .strongReference(true)
                .register(meterRegistry);
        new ClassLoaderMetrics().bindTo(meterRegistry);
        new JvmGcMetrics().bindTo(meterRegistry);
        new JvmInfoMetrics().bindTo(meterRegistry);
        new JvmMemoryMetrics().bindTo(meterRegistry);
        new JvmThreadMetrics().bindTo(meterRegistry);
        new ProcessorMetrics().bindTo(meterRegistry);
        new ProcessMemoryMetrics().bindTo(meterRegistry);
        new ProcessThreadMetrics().bindTo(meterRegistry);
        new UptimeMetrics().bindTo(meterRegistry);
    }

}
