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
package org.dependencytrack.vulnanalysis;

import org.cyclonedx.proto.v1_7.Bom;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.config.UnresolvableSecretException;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.InvokeVulnAnalyzerArg;
import org.dependencytrack.proto.internal.workflow.v1.InvokeVulnAnalyzerRes;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.NoSuchFileException;
import java.util.Map;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ANALYZER_NAME;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "invoke-vuln-analyzer", defaultTaskQueue = "vuln-analyses")
public final class InvokeVulnAnalyzerActivity implements Activity<InvokeVulnAnalyzerArg, InvokeVulnAnalyzerRes> {

    private static final Logger LOGGER = LoggerFactory.getLogger(InvokeVulnAnalyzerActivity.class);

    private final FileStorage fileStorage;
    private final PluginManager pluginManager;

    public InvokeVulnAnalyzerActivity(FileStorage fileStorage, PluginManager pluginManager) {
        this.fileStorage = fileStorage;
        this.pluginManager = pluginManager;
    }

    @Override
    public InvokeVulnAnalyzerRes execute(
            ActivityContext ctx,
            @Nullable InvokeVulnAnalyzerArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var _ = new MdcScope(Map.ofEntries(
                Map.entry(MDC_PROJECT_UUID, arg.getProjectUuid()),
                Map.entry(MDC_VULN_ANALYZER_NAME, arg.getAnalyzerName())))) {
            LOGGER.debug("Retrieving BOM from {}", arg.getBomFileMetadata().getLocation());
            final Bom bom = getBom(arg.getBomFileMetadata());

            LOGGER.debug("Invoking analyzer");
            final Bom vdr = performAnalysis(arg.getAnalyzerName(), bom);
            if (vdr == null) {
                throw new TerminalApplicationFailureException("Analyzer did not return any result");
            }
            LOGGER.debug("Analyzer identified {} vulnerabilities", vdr.getVulnerabilitiesCount());

            // Minor optimization: Do not bother file storage with files that are
            // effectively empty. The fact that a response is returned at all is
            // enough indication that the analyzer succeeded.
            if (vdr.getVulnerabilitiesCount() == 0) {
                LOGGER.debug("Not storing VDR file because no vulnerabilities were found");
                return InvokeVulnAnalyzerRes.newBuilder().build();
            }

            LOGGER.debug("Storing VDR file in file storage");
            final FileMetadata vdrFileMetadata = storeVdr(ctx, arg.getAnalyzerName(), vdr);
            LOGGER.debug("Stored VDR file at {}", vdrFileMetadata.getLocation());

            return InvokeVulnAnalyzerRes.newBuilder()
                    .setVdrFileMetadata(vdrFileMetadata)
                    .buildPartial();
        }
    }

    private Bom getBom(FileMetadata fileMetadata) throws IOException {
        try (final InputStream bomInputStream = fileStorage.get(fileMetadata)) {
            return Bom.parseFrom(bomInputStream);
        } catch (NoSuchFileException | NoSuchExtensionException e) {
            throw new TerminalApplicationFailureException(e);
        }
    }

    private Bom performAnalysis(String analyzerName, Bom bom) throws InterruptedException {
        try (final var vulnAnalyzer = pluginManager.getExtension(VulnAnalyzer.class, analyzerName)) {
            return vulnAnalyzer.analyze(bom);
        } catch (NoSuchExtensionException
                 | InvalidRuntimeConfigException
                 | UnresolvableSecretException e) {
            throw new TerminalApplicationFailureException(e);
        }
    }

    private FileMetadata storeVdr(ActivityContext ctx, String analyzerName, Bom vdr) throws IOException {
        return fileStorage.store(
                "vuln-analysis/%s/vdr_%s.proto".formatted(ctx.workflowRunId(), analyzerName),
                "application/protobuf",
                new ByteArrayInputStream(vdr.toByteArray()));
    }

}
