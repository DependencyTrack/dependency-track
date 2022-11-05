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
package org.dependencytrack.persistence.defaults;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import org.apache.commons.io.IOUtils;
import org.cyclonedx.BomParserFactory;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.Parser;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.QueryManager;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * @since 4.7.0
 */
public class DefaultProjectImporter implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(DefaultProjectImporter.class);
    private static final String DEFAULT_SBOM_PATH = ".well-known/sbom";

    private final Config config;
    private final String sbomPath;

    public DefaultProjectImporter() {
        this(Config.getInstance(), DEFAULT_SBOM_PATH);
    }

    DefaultProjectImporter(final Config config, final String sbomPath) {
        this.config = config;
        this.sbomPath = sbomPath;
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (config.getPropertyAsBoolean(ConfigKey.DEFAULT_PROJECT_DISABLE)) {
            LOGGER.debug("Default project creation is disabled");
            return;
        }

        final URL sbomUrl = getClass().getClassLoader().getResource(sbomPath);
        if (sbomUrl == null) {
            LOGGER.warn("Cannot create default project because the SBOM %s was not found".formatted(sbomPath));
            return;
        }

        final byte[] bomBytes;
        final org.cyclonedx.model.Component bomComponent;
        try {
            bomBytes = IOUtils.toByteArray(sbomUrl);
            final Parser bomParser = BomParserFactory.createParser(bomBytes);
            bomComponent = bomParser.parse(bomBytes).getMetadata().getComponent();
        } catch (IOException | ParseException e) {
            LOGGER.error("An unexpected error occurred while parsing the default project SBOM", e);
            return;
        }

        try (final var qm = new QueryManager()) {
            Project project = qm.getProject(bomComponent.getName(), bomComponent.getVersion());
            if (project != null) {
                LOGGER.info("Default project already exists");
                return;
            }

            LOGGER.info("Creating default project %s %s".formatted(bomComponent.getName(), bomComponent.getVersion()));
            project = new Project();
            project.setPublisher(bomComponent.getPublisher());
            project.setGroup(bomComponent.getGroup());
            project.setName(bomComponent.getName());
            project.setVersion(bomComponent.getVersion());
            project.setClassifier(Classifier.APPLICATION);
            project.setDescription(bomComponent.getDescription());
            project.setPurl(bomComponent.getPurl());
            project.setActive(true);
            project = qm.createProject(project, getConfiguredTags(), true);

            LOGGER.info("Dispatching BOM upload event for default project");
            Event.dispatch(new BomUploadEvent(project.getUuid(), bomBytes));
        }
    }

    private List<Tag> getConfiguredTags() {
        return Optional.ofNullable(config.getProperty(ConfigKey.DEFAULT_PROJECT_TAGS)).stream()
                .flatMap(tagNames -> Arrays.stream(tagNames.split(",")))
                .map(tagName -> {
                    final var tag = new Tag();
                    tag.setName(tagName);
                    return tag;
                })
                .toList();
    }

}
