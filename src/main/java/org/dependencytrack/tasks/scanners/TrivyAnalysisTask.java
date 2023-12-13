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
package org.dependencytrack.tasks.scanners;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.common.util.UrlUtil;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.security.crypto.DataEncryption;
import com.github.packageurl.PackageURL;
import com.google.gson.Gson;
import io.github.resilience4j.micrometer.tagged.TaggedRetryMetrics;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.TrivyAnalysisEvent;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.Vulnerability.Source;
import org.dependencytrack.parser.trivy.model.Application;
import org.dependencytrack.parser.trivy.model.OS;
import org.dependencytrack.parser.trivy.model.BlobInfo;
import org.dependencytrack.parser.trivy.model.DeleteRequest;
import org.dependencytrack.parser.trivy.model.Library;
import org.dependencytrack.parser.trivy.model.Options;
import org.dependencytrack.parser.trivy.model.PackageInfo;
import org.dependencytrack.parser.trivy.model.PurlType;
import org.dependencytrack.parser.trivy.model.PutRequest;
import org.dependencytrack.parser.trivy.model.ScanRequest;
import org.dependencytrack.parser.trivy.model.TrivyResponse;
import org.dependencytrack.parser.trivy.model.Package;
import org.dependencytrack.parser.trivy.TrivyParser;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.dependencytrack.util.RoundRobinAccessor;


/**
 * Subscriber task that performs an analysis of component using Trivy vulnerability API.
 *
 * @since 4.7.0
 */
public class TrivyAnalysisTask extends BaseComponentAnalyzerTask implements CacheableScanTask, Subscriber {

    private static final Logger LOGGER = Logger.getLogger(TrivyAnalysisTask.class);
    private static final String TOKEN_HEADER = "Trivy-Token";
    private static final Retry RETRY;
    private static final ExecutorService EXECUTOR;

    static {
        final RetryRegistry retryRegistry = RetryRegistry.of(RetryConfig.<CloseableHttpResponse>custom()
                .retryOnException(exception -> false)
                .retryOnResult(response -> 429 == response.getStatusLine().getStatusCode())
                .build());
        RETRY = retryRegistry.retry("trivy-api");
        RETRY.getEventPublisher()
                .onRetry(event -> LOGGER.debug("Will execute retry #%d in %s" .formatted(event.getNumberOfRetryAttempts(), event.getWaitInterval())))
                .onError(event -> LOGGER.error("Retry failed after %d attempts: %s" .formatted(event.getNumberOfRetryAttempts(), event.getLastThrowable())));
        TaggedRetryMetrics.ofRetryRegistry(retryRegistry)
                .bindTo(Metrics.getRegistry());

        // The number of threads to be used for Trivy analyzer are configurable.
        // Default is 10. Can be set based on user requirements.
        final int threadPoolSize = 10;
        final var threadFactory = new BasicThreadFactory.Builder()
                .namingPattern(TrivyAnalysisTask.class.getSimpleName() + "-%d")
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .build();
        EXECUTOR = Executors.newFixedThreadPool(threadPoolSize, threadFactory);
        Metrics.registerExecutorService(EXECUTOR, TrivyAnalysisTask.class.getSimpleName());
    }

    private String apiBaseUrl;
    private Supplier<String> apiTokenSupplier;
    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (e instanceof final TrivyAnalysisEvent event) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_TRIVY_ENABLED)) {
                return;
            }
            try (QueryManager qm = new QueryManager()) {
                final ConfigProperty apiTokenProperty = qm.getConfigProperty(
                        ConfigPropertyConstants.SCANNER_TRIVY_API_TOKEN.getGroupName(),
                        ConfigPropertyConstants.SCANNER_TRIVY_API_TOKEN.getPropertyName()
                );

                if (apiTokenProperty == null || apiTokenProperty.getPropertyValue() == null) {
                    LOGGER.warn("No API token provided; Skipping");
                    return;
                }
                if (getApiBaseUrl().isEmpty()) {
                    LOGGER.warn("No API base URL provided; Skipping");
                    return;
                }

                apiBaseUrl = getApiBaseUrl().get();

                try {
                    final String decryptedToken = DataEncryption.decryptAsString(apiTokenProperty.getPropertyValue());
                    apiTokenSupplier = createTokenSupplier(decryptedToken);
                } catch (Exception ex) {
                    LOGGER.error("An error occurred decrypting the API Token; Skipping", ex);
                    return;
                }
            }
            vulnerabilityAnalysisLevel = event.getVulnerabilityAnalysisLevel();
            LOGGER.info("Starting Trivy vulnerability analysis task");
            if (!event.getComponents().isEmpty()) {
                analyze(event.getComponents());
            }
            LOGGER.info("Trivy vulnerability analysis complete");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.TRIVY_ANALYZER;
    }

    @Override
    public boolean isCapable(Component component) {
        final boolean hasValidPurl = component.getPurl() != null
        && component.getPurl().getScheme() != null
        && component.getPurl().getType() != null
        && component.getPurl().getName() != null
        && component.getPurl().getVersion() != null;

        if (!hasValidPurl && component.getPurl() == null) {
            LOGGER.warn("isCapable:purl is null for component %s".formatted(component.toString()));
        } else if (!hasValidPurl) {
            LOGGER.warn("isCapable: " + component.getPurl().toString());
        }

        return (hasValidPurl && PurlType.getApp(component.getPurl().getType()) != PurlType.Constants.UNKNOWN.toString())
        || component.getClassifier() == Classifier.OPERATING_SYSTEM;
    }

    @Override
    protected boolean isCacheCurrent(Source source, String targetHost, String target) {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void analyze(final List<Component> components) {
        final var countDownLatch = new CountDownLatch(components.size());



        var pkgs = new HashMap<String, PackageInfo>();
        var apps = new HashMap<String, Application>();
        var os = new HashMap<String, OS>();
        var map = new HashMap<String, Component>();

        for (final Component component : components) {
            if (component.getPurl() != null) {
                var appType = PurlType.getApp(component.getPurl().getType());

                var name = component.getName();

                if (component.getGroup() != null) {
                    name = component.getGroup() + ":" + name;
                }

                if (appType != PurlType.UNKNOWN.getAppType()) {
                    if (appType != "packages") {

                        if (apps.get(appType) == null) {
                            apps.put(appType, new Application(appType));
                        }
                        var app = apps.get(appType);

                        var key = name + ":" + component.getVersion();

                        LOGGER.debug("Add key %s to map".formatted(key));
                        map.put(key, component);

                        LOGGER.debug("add library %s".formatted(component.toString()));
                        app.addLibrary(new Library(name, component.getVersion()));
                    } else {
                        var pkgType = component.getPurl().getType().toString();

                        String arch = null;
                        Integer epoch = null;
                        String versionKey = "";

                        if (component.getPurl().getQualifiers() != null) {
                            arch = component.getPurl().getQualifiers().get("arch");

                            String tmpEpoch = component.getPurl().getQualifiers().get("epoch");
                            if (tmpEpoch != null) {
                                epoch = Integer.parseInt(tmpEpoch);
                                versionKey = tmpEpoch + ":";
                            }

                            String distro = component.getPurl().getQualifiers().get("distro");

                            if (distro != null) {
                                pkgType = distro;
                            }
                        }

                         if (pkgs.get(pkgType) == null) {
                            pkgs.put(pkgType, new PackageInfo());
                        }

                        var pkg = pkgs.get(pkgType);

                        versionKey += component.getVersion();
                        var key = name + ":" + versionKey;

                        LOGGER.debug("Add key %s to map".formatted(key));
                        map.put(key, component);
                        LOGGER.debug("add package %s".formatted(component.toString()));
                        pkg.addPackage(new Package(component.getName(), component.getVersion(),  arch != null ? arch : "x86_64", epoch));
                    }
                }

            } else if (component.getClassifier() == Classifier.OPERATING_SYSTEM) {
                LOGGER.debug("add operative system %s".formatted(component.toString()));
                var key = "%s-%s".formatted(component.getName(), component.getVersion());
                os.put(key, new OS(component.getName(), component.getVersion()));
            }
        }

        ArrayList<BlobInfo> infos = new ArrayList<BlobInfo>();

        if (apps.size() > 0) {
            var info = new BlobInfo();
            info.setApplications(apps.values().toArray(new Application[]{}));
            infos.add(info);
        }

        pkgs.forEach((key, value) -> {
            var info = new BlobInfo();
            info.setPackageInfos(new PackageInfo[]{value});
            if (os.get(key) != null) {
                info.setOS(os.get(key));
            }
            infos.add(info);
        });

        CompletableFuture
                    .runAsync(() -> analyzeBlob(map, infos.toArray(new BlobInfo[]{})), EXECUTOR)
                    .whenComplete((result, exception) -> {
                        countDownLatch.countDown();

                        if (exception != null) {
                            LOGGER.error("An unexpected error occurred while analyzing", exception);
                        }
                    });

        try {
            if (!countDownLatch.await(60, TimeUnit.MINUTES)) {
                // Depending on the system load, it may take a while for the queued events
                // to be processed. And depending on how large the projects are, it may take a
                // while for the processing of the respective event to complete.
                // It is unlikely though that either of these situations causes a block for
                // over 60 minutes. If that happens, the system is under-resourced.
                LOGGER.warn("The Analysis for project :" + components.get(0).getProject().getName() + "took longer than expected");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean shouldAnalyze(final PackageURL packageUrl) {
        return getApiBaseUrl()
                .map(baseUrl -> !isCacheCurrent(Vulnerability.Source.NVD, apiBaseUrl, packageUrl.getCoordinates()))
                .orElse(false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void applyAnalysisFromCache(final Component component) {
        getApiBaseUrl().ifPresent(baseUrl ->
                applyAnalysisFromCache(Vulnerability.Source.NVD, apiBaseUrl,
                        component.getPurl().getCoordinates(), component, getAnalyzerIdentity(), vulnerabilityAnalysisLevel));
    }

    private void analyzeBlob(final Map<String, Component> components, final BlobInfo[] blobs) {
        for (final BlobInfo info : blobs) {

            var blob = new PutRequest();
            blob.setBlobInfo(info);

            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                //todo - need to establish standard and requirements from trivy
                byte[] hash = digest.digest(java.util.UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));

                blob.setDiffID("sha256:" + Hex.encodeHexString(hash));
                LOGGER.debug(blob.getDiffID());
            } catch(NoSuchAlgorithmException e) {
                LOGGER.error(e.getMessage());
                blob.setDiffID("sha256:0000000000000000000000000000000000000000000000000000000000000000");
            }

            if (putBlob(blob)) {
                var response = scanBlob(blob);
                if (response != null) {
                    LOGGER.info("received response from trivy");
                    for (int count = 0; count < response.getResults().length; count++) {
                        var result = response.getResults()[count];
                        for (int idx = 0; idx < result.getVulnerabilities().length; idx++) {
                            var vulnerability = result.getVulnerabilities()[idx];
                            var key = vulnerability.getPkgName() + ":" + vulnerability.getInstalledVersion();
                            LOGGER.debug("Searching key %s in map".formatted(key));
                            handle(components.get(key), vulnerability);
                        }
                    }
                }
                deleteBlob(blob);
            }
        }
    }

    private boolean putBlob(PutRequest input) {
        final String requestUrl = "%s/twirp/trivy.cache.v1.Cache/PutBlob".formatted(apiBaseUrl);

         try {
            URIBuilder uriBuilder = new URIBuilder(requestUrl);
            HttpPost post = new HttpPost(uriBuilder.build().toString());


            Gson gson = new Gson();
            StringEntity body = new StringEntity(gson.toJson(input));
            post.setEntity(body);

            LOGGER.debug("PutBlob request: " + gson.toJson(input));

            HttpUriRequest request = post;

            request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
            request.setHeader(TOKEN_HEADER, apiTokenSupplier.get());
            request.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            try (final CloseableHttpResponse response = RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request))) {
                LOGGER.info("PutBlob response: " + response.getStatusLine().getStatusCode());
                return (response.getStatusLine().getStatusCode() >= HttpStatus.SC_OK);
            }
        } catch (Throwable  ex) {
            handleRequestException(LOGGER, ex);
        }
        return false;
    }

    private TrivyResponse scanBlob(PutRequest input) {
        final String requestUrl = "%s/twirp/trivy.scanner.v1.Scanner/Scan".formatted(apiBaseUrl);

         try {
            URIBuilder uriBuilder = new URIBuilder(requestUrl);
            HttpPost post = new HttpPost(uriBuilder.build().toString());

            ScanRequest scan = new ScanRequest();

            scan.setTarget(input.getDiffID());
            scan.setArtifactID(input.getDiffID());
            scan.setBlobIDS(new String[] {input.getDiffID()});

            Options opts = new Options();
            opts.setVulnType(new String[] {"os", "library"});
            opts.setScanners(new String[] {"vuln"});

            scan.setOptions(opts);

            Gson gson = new Gson();
            StringEntity body = new StringEntity(gson.toJson(scan));
            post.setEntity(body);

            LOGGER.debug("Scan request: " + gson.toJson(scan));

            HttpUriRequest request = post;

            request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
            request.setHeader(TOKEN_HEADER, apiTokenSupplier.get());
            request.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            try (final CloseableHttpResponse response = RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request))) {


                if (response.getStatusLine().getStatusCode() >= HttpStatus.SC_OK && response.getStatusLine().getStatusCode() < HttpStatus.SC_MULTIPLE_CHOICES) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    var trivyResponse = gson.fromJson(responseString,TrivyResponse.class);

                    LOGGER.info("Scan response: " + response.getStatusLine().getStatusCode());
                    LOGGER.debug("Response from server: " + responseString);
                    return trivyResponse;
                } else {
                    handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
                }
            }
        } catch (Throwable  ex) {
            handleRequestException(LOGGER, ex);
        }
        return null;
    }

    private void deleteBlob(PutRequest input) {
        final String requestUrl = "%s/twirp/trivy.cache.v1.Cache/DeleteBlobs".formatted(apiBaseUrl);

         try {
            URIBuilder uriBuilder = new URIBuilder(requestUrl);
            HttpPost post = new HttpPost(uriBuilder.build().toString());

            DeleteRequest delete = new DeleteRequest();
            delete.setBlobIDS(new String[] {input.getDiffID()});

            Gson gson = new Gson();

            StringEntity body = new StringEntity(gson.toJson(delete));
            post.setEntity(body);

            LOGGER.debug("Delete Request: " + gson.toJson(delete));

            HttpUriRequest request = post;

            request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
            request.setHeader(TOKEN_HEADER, apiTokenSupplier.get());
            request.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            final CloseableHttpResponse response = RETRY.executeCheckedSupplier(() -> HttpClientPool.getClient().execute(request));
            LOGGER.info("DeleteBlob response: " + response.getStatusLine().getStatusCode());
        } catch (Throwable  ex) {
            handleRequestException(LOGGER, ex);
        }

    }

    private void handle(final Component component, final org.dependencytrack.parser.trivy.model.Vulnerability data) {
        if (component == null) {
            LOGGER.error("Unable to handle null component");
            return;
        } else if (data == null) {
            addNoVulnerabilityToCache(component);
            return;
        }

        try (QueryManager qm = new QueryManager()) {
            final var trivyParser = new TrivyParser();

            Vulnerability synchronizedVulnerability = trivyParser.parse(data, qm);
            addVulnerabilityToCache(component, synchronizedVulnerability);
            final Component componentPersisted = qm.getObjectByUuid(Component.class, component.getUuid());
            if (componentPersisted != null && synchronizedVulnerability.getVulnId() != null) {
                NotificationUtil.analyzeNotificationCriteria(qm, synchronizedVulnerability, componentPersisted, vulnerabilityAnalysisLevel);
                qm.addVulnerability(synchronizedVulnerability, componentPersisted, this.getAnalyzerIdentity());
                LOGGER.info("Trivy vulnerability added : " + synchronizedVulnerability.getVulnId() + " to component " + component.getName());
            }
            Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));

            updateAnalysisCacheStats(qm, Vulnerability.Source.NVD, apiBaseUrl, component.getPurl().getCoordinates(), component.getCacheResult());
        }
    }



    private Optional<String> getApiBaseUrl() {
        if (apiBaseUrl != null) {
            return Optional.of(apiBaseUrl);
        }

        try (final var qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(
                    ConfigPropertyConstants.SCANNER_TRIVY_BASE_URL.getGroupName(),
                    ConfigPropertyConstants.SCANNER_TRIVY_BASE_URL.getPropertyName()
            );
            if (property == null) {
                return Optional.empty();
            }

            apiBaseUrl = UrlUtil.normalize(property.getPropertyValue());
            return Optional.of(apiBaseUrl);
        }
    }

    private Supplier<String> createTokenSupplier(final String tokenValue) {
        final String[] tokens = tokenValue.split(";");
        if (tokens.length > 1) {
            LOGGER.debug("Will use %d tokens in round robin" .formatted(tokens.length));
            final var roundRobinAccessor = new RoundRobinAccessor<>(List.of(tokens));
            return roundRobinAccessor::get;
        }

        return apiTokenSupplier = () -> tokenValue;
    }

}
