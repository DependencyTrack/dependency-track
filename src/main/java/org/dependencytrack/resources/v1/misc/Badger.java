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
package org.dependencytrack.resources.v1.misc;

import alpine.logging.Logger;
import com.mitchellbosecke.pebble.PebbleEngine;
import com.mitchellbosecke.pebble.template.PebbleTemplate;
import org.dependencytrack.model.ProjectMetrics;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

/**
 * Creates svg badges from various metrics for display on external sites.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class Badger {

    private static final PebbleEngine ENGINE = new PebbleEngine.Builder().newLineTrimming(false).build();
    private static final PebbleTemplate PROJECT_VULNS_TEMPLATE = ENGINE.getTemplate("templates/badge/project-vulns.peb");
    private static final PebbleTemplate PROJECT_NO_VULNS_TEMPLATE = ENGINE.getTemplate("templates/badge/project-novulns.peb");
    private static final PebbleTemplate PROJECT_NO_METRICS_TEMPLATE = ENGINE.getTemplate("templates/badge/project-nometrics.peb");

    public String generate(ProjectMetrics metrics) {
        final Map<String, Object> context = new HashMap<>();
        context.put("roundedPixels", "3");
        if (metrics == null) {
            return writeSvg(PROJECT_NO_METRICS_TEMPLATE, context);
        } else if (metrics.getVulnerabilities() > 0) {
            context.put("critical", String.valueOf(metrics.getCritical()));
            context.put("high", String.valueOf(metrics.getHigh()));
            context.put("medium", String.valueOf(metrics.getMedium()));
            context.put("low", String.valueOf(metrics.getLow()));
            context.put("unassigned", String.valueOf(metrics.getUnassigned()));
            return writeSvg(PROJECT_VULNS_TEMPLATE, context);
        } else {
            return writeSvg(PROJECT_NO_VULNS_TEMPLATE, context);
        }
    }

    private String writeSvg(PebbleTemplate template, Map<String, Object> context) {
        try (Writer writer = new StringWriter()) {
            template.evaluate(writer, context);
            return writer.toString();
        } catch (IOException e) {
            Logger.getLogger(this.getClass()).error("An error was encountered evaluating template", e);
            return null;
        }
    }
}


