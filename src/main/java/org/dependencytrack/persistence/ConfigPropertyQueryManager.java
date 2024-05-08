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
package org.dependencytrack.persistence;

import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_NPMAUDIT_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_SNYK_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_TRIVY_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_VULNDB_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_API_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_INTERNAL_DEDUPLICATES_ENABLED;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;



import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.resources.v1.ConfigPropertyResource;

import alpine.model.ConfigProperty;

public class ConfigPropertyQueryManager extends ConfigPropertyResource{
    private static final ConfigPropertyConstants[] constantFlags = {
        SCANNER_INTERNAL_ENABLED,
        SCANNER_NPMAUDIT_ENABLED,
        SCANNER_OSSINDEX_ALIAS_SYNC_ENABLED, //NEEDS SCANNER_OSSINDEX_ENABLED
        SCANNER_VULNDB_ENABLED,
        SCANNER_SNYK_ALIAS_SYNC_ENABLED, //NEEDS SCANNER_SNYK_ENABLED
        SCANNER_TRIVY_ENABLED,
        VULNERABILITY_SOURCE_NVD_API_ENABLED, //VULNERABILITY_SOURCE_NVD_ENABLED
        VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED, //NEEDS VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED
        VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED //NEEDS VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED
    };

    private static final Map<ConfigPropertyConstants, ConfigPropertyConstants> needsDependency = new HashMap<ConfigPropertyConstants, ConfigPropertyConstants>() {{
        put(SCANNER_OSSINDEX_ALIAS_SYNC_ENABLED, SCANNER_OSSINDEX_ENABLED);
        put(SCANNER_SNYK_ALIAS_SYNC_ENABLED, SCANNER_SNYK_ENABLED);
        put(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED, VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED);
        put(VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED, VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED);
    }};

    public void updatePropertiesFromEnabledSources(){
        List<String> sourcesList = retrieveEnabledSources()
        .stream()
        .map(Vulnerability.Source::toString)
        .collect(Collectors.toList());

        updateProperties(sourcesList);
    }

    public List<Vulnerability.Source> retrieveEnabledSources(){
        Map<ConfigPropertyConstants, Vulnerability.Source> constantsMap = createConstantsMapFromEnum();
        List<Vulnerability.Source> enabledSources = new ArrayList<>();
        try (final QueryManager qm = new QueryManager()) {
            for ( ConfigPropertyConstants constantFlag : constantsMap.keySet()){
                if(isEnabled(qm,constantFlag)){
                    enabledSources.add(constantsMap.get(constantFlag));
                }
            }
            return enabledSources;
        }

    }

    private boolean isEnabled(QueryManager qm, ConfigPropertyConstants constantFlag) {
        boolean flagEnabled = qm.isEnabled(constantFlag);
        ConfigPropertyConstants dependentFlag = needsDependency.get(constantFlag);
        return flagEnabled && (dependentFlag != null ? qm.isEnabled(dependentFlag) : true);
    }

    public void updateProperties(List<String> sourcesList) {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty property = makeQuery(qm, SCANNER_INTERNAL_DEDUPLICATES);
            List<String> priorityList = Arrays.stream(property.getPropertyValue().split(";"))
                    .collect(Collectors.toList());
            priorityList = Stream.concat(priorityList.stream(), sourcesList.stream())
                    .distinct()
                    .filter(sourcesList::contains)
                    .collect(Collectors.toList());
            property.setPropertyValue(String.join(";", priorityList));
            qm.persist(property);
        }
    }

    public boolean isDedupEnabled(){
        try (final QueryManager qm = new QueryManager()) {
            return qm.isEnabled(SCANNER_INTERNAL_DEDUPLICATES_ENABLED);
        }
    }

    public List<Vulnerability.Source> parsePriorityList() {
        try (final QueryManager qm = new QueryManager()) {
            String result = makeQuery(qm, SCANNER_INTERNAL_DEDUPLICATES).getPropertyValue();

            if (result == null || result.isEmpty() || !isDedupEnabled()) {
                return new ArrayList<>();
            }

            return Arrays.stream(result.split(";"))
                    .map(String::trim)
                    .map(String::toUpperCase)
                    .map(Vulnerability.Source::valueOf)
                    .collect(Collectors.toList());
        }
    }

    private static Map<ConfigPropertyConstants, Vulnerability.Source> createConstantsMapFromEnum() {
        Map<ConfigPropertyConstants, Vulnerability.Source> constantsMap = new HashMap<>();
        for (Vulnerability.Source source : Vulnerability.Source.values()) {
            ConfigPropertyConstants constantFlag = findMatchingConstantFlag(source);
            if (constantFlag != null) {
                constantsMap.put(constantFlag, source);
            }
        }
        return constantsMap;
    }

    private static ConfigPropertyConstants findMatchingConstantFlag(Vulnerability.Source source) {
        for (ConfigPropertyConstants constantFlag : constantFlags) {
            if (constantFlag.toString().contains(source.toString())) {
                return constantFlag;
            }
        }
        return null;
    }

    private ConfigProperty makeQuery(QueryManager qm, ConfigPropertyConstants constantFlag) {
        final ConfigProperty configProperty = qm.getConfigProperty(constantFlag.getGroupName(), constantFlag.getPropertyName());
        return configProperty;
    }
}
