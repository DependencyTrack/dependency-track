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
package org.dependencytrack.integrations;

import alpine.model.About;
import alpine.model.ConfigProperty;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.DateUtil;
import org.json.JSONObject;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BASE_URL;

public class FindingPackagingFormat {

    /** FPF is versioned. If the format changes, the version needs to be bumped. */
    private static final String FPF_VERSION = "1.0";
    private static final String FIELD_APPLICATION = "application";
    private static final String FIELD_VERSION = "version";
    private static final String FIELD_TIMESTAMP = "timestamp";
    private static final String FIELD_BASE_URL = "baseUrl";
    private static final String FIELD_UUID = "uuid";
    private static final String FIELD_DESCRIPTION = "description";
    private static final String FIELD_NAME = "name";
    private static final String FIELD_PURL = "purl";
    private static final String FIELD_META = "meta";
    private static final String FIELD_PROJECT = "project";
    private static final String FIELD_FINDINGS = "findings";

    private final JSONObject payload;

    public FindingPackagingFormat(final UUID projectUuid, final List<Finding> findings) {
        payload = initialize(projectUuid, findings);
    }

    public JSONObject getDocument() {
        return payload;
    }

    private JSONObject initialize(final UUID projectUuid, final List<Finding> findings) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            final About about = new About();
            final ConfigProperty baseUrl = qm.getConfigProperty(GENERAL_BASE_URL.getGroupName(), GENERAL_BASE_URL.getPropertyName());

            /*
                Create a generic meta object containing basic Dependency-Track information
                This is useful for file-based parsing systems that needs to be able to
                identify what type of file it is, and what type of system generated it.
             */
            final JSONObject meta = new JSONObject();
            meta.put(FIELD_APPLICATION, about.getApplication());
            meta.put(FIELD_VERSION, about.getVersion());
            meta.put(FIELD_TIMESTAMP, DateUtil.toISO8601(new Date()));
            if (baseUrl != null && baseUrl.getPropertyValue() != null) {
                meta.put(FIELD_BASE_URL, baseUrl.getPropertyValue());
            }


            /*
                Findings are specific to a given project. This information is useful for
                systems outside of Dependency-Track so that they can perform mappings as
                well as not have to perform additional queries back to Dependency-Track
                to discover basic project information.
             */
            final JSONObject projectJson = new JSONObject();
            projectJson.put(FIELD_UUID, project.getUuid());
            projectJson.put(FIELD_NAME, project.getName());
            if (project.getVersion() != null) {
                projectJson.put(FIELD_VERSION, project.getVersion());
            }
            if (project.getDescription() != null) {
                projectJson.put(FIELD_DESCRIPTION, project.getDescription());
            }
            if (project.getPurl() != null) {
                projectJson.put(FIELD_PURL, project.getPurl());
            }


            /*
                Add the meta and project objects along with the findings array
                to a root json object and return.
             */
            final JSONObject root = new JSONObject();
            root.put(FIELD_VERSION, FPF_VERSION);
            root.put(FIELD_META, meta);
            root.put(FIELD_PROJECT, projectJson);
            root.put(FIELD_FINDINGS, findings);
            return root;
        }
    }
}
