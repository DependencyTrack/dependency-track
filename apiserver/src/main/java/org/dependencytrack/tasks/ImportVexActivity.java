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
package org.dependencytrack.tasks;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.BomParserFactory;
import org.cyclonedx.parsers.Parser;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vex;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.parser.cyclonedx.CycloneDXVexImporter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.internal.workflow.v1.ImportVexArg;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.InputStream;
import java.nio.file.NoSuchFileException;
import java.util.Date;
import java.util.UUID;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.common.MdcKeys.MDC_VEX_UPLOAD_TOKEN;
import static org.dependencytrack.notification.api.NotificationFactory.createVexConsumedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createVexProcessedNotification;

/**
 * @since 5.0.0
 */
@NullMarked
@ActivitySpec(name = "import-vex", defaultTaskQueue = "artifact-imports")
public final class ImportVexActivity implements Activity<ImportVexArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ImportVexActivity.class);

    private final FileStorage fileStorage;

    public ImportVexActivity(FileStorage fileStorage) {
        this.fileStorage = fileStorage;
    }

    @Override
    public @Nullable Void execute(ActivityContext ctx, @Nullable ImportVexArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, arg.getProjectUuid());
             var ignoredMdcProjectName = MDC.putCloseable(MDC_PROJECT_NAME, arg.getProjectName());
             var ignoredMdcProjectVersion = MDC.putCloseable(MDC_PROJECT_VERSION, arg.getProjectVersion());
             var ignoredMdcVexUploadToken = MDC.putCloseable(MDC_VEX_UPLOAD_TOKEN, arg.getVexUploadToken())) {
            final byte[] vexBytes;
            try (final InputStream vexStream = fileStorage.get(arg.getVexFileMetadata())) {
                vexBytes = vexStream.readAllBytes();
            } catch (NoSuchFileException e) {
                throw new TerminalApplicationFailureException(e);
            }

            process(UUID.fromString(arg.getProjectUuid()), vexBytes);
        }

        return null;
    }

    private void process(UUID projectUuid, byte[] vexBytes) {
        try (final QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (project == null) {
                throw new TerminalApplicationFailureException(
                        "Project %s does not exist".formatted(projectUuid));
            }

            LOGGER.info("Processing CycloneDX VEX uploaded.");
            final Vex vex = new Vex();
            vex.setProject(project);
            vex.setImported(new Date());
            vex.setVexFormat(Vex.Format.CYCLONEDX);

            final Bom bom;
            try {
                final Parser parser = BomParserFactory.createParser(vexBytes);
                bom = parser.parse(vexBytes);
            } catch (ParseException e) {
                throw new TerminalApplicationFailureException("Failed to parse VEX", e);
            }
            vex.setSpecVersion(bom.getSpecVersion());
            vex.setVexVersion(bom.getVersion());
            vex.setSerialNumber(bom.getSerialNumber());

            final CycloneDXVexImporter vexImporter = new CycloneDXVexImporter();
            qm.runInTransaction(() -> vexImporter.applyVex(qm, bom, project));
            LOGGER.info("Completed processing of CycloneDX VEX");

            final var notificationEmitter = new JdoNotificationEmitter(qm);

            notificationEmitter.emit(
                    createVexConsumedNotification(
                            NotificationModelConverter.convert(project),
                            NotificationModelConverter.convert(vex)));
            qm.persist(vex);

            notificationEmitter.emit(
                    createVexProcessedNotification(
                            NotificationModelConverter.convert(project),
                            NotificationModelConverter.convert(vex)));
        }
    }

}
