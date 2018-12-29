/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
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

    private final JSONObject payload;

    public FindingPackagingFormat(UUID projectUuid, List<Finding> findings) {
        payload = initialize(projectUuid, findings);
    }

    public JSONObject getDocument() {
        return payload;
    }

    private JSONObject initialize(UUID projectUuid, List<Finding> findings) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            final About about = new About();
            ConfigProperty baseUrl = qm.getConfigProperty(GENERAL_BASE_URL.getGroupName(), GENERAL_BASE_URL.getPropertyName());

            /*
                Create a generic meta object containing basic Dependency-Track information
                This is useful for file-based parsing systems that needs to be able to
                identify what type of file it is, and what type of system generated it.
             */
            JSONObject meta = new JSONObject();
            meta.put("application", about.getApplication());
            meta.put("version", about.getVersion());
            meta.put("timestamp", DateUtil.toISO8601(new Date()));
            if (baseUrl != null && baseUrl.getPropertyValue() != null) {
                meta.put("baseUrl", baseUrl.getPropertyValue());
            }


            /*
                Findings are specific to a given project. This information is useful for
                systems outside of Dependency-Track so that they can perform mappings as
                well as not have to perform additional queries back to Dependency-Track
                to discover basic project information.
             */
            JSONObject projectJson = new JSONObject();
            projectJson.put("uuid", project.getUuid());
            projectJson.put("name", project.getName());
            if (project.getVersion() != null) {
                projectJson.put("version", project.getVersion());
            }
            if (project.getDescription() != null) {
                projectJson.put("description", project.getDescription());
            }
            if (project.getPurl() != null) {
                projectJson.put("purl", project.getPurl());
            }


            /*
                Add the meta and project objects along with the findings array
                to a root json object and return.
             */
            JSONObject root = new JSONObject();
            root.put("version", FPF_VERSION);
            root.put("meta", meta);
            root.put("project", projectJson);
            root.put("findings", findings);
            return root;
        }
    }
}
