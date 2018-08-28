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
package org.dependencytrack.notification;

import com.mitchellbosecke.pebble.extension.escaper.EscapingStrategy;
import org.unbescape.json.JsonEscape;

/*
 * TODO: Remove once https://github.com/PebbleTemplates/pebble/issues/395 is complete
 */
public class JsonEscapingStrategy implements EscapingStrategy {

    public String escape(String var1) {
        return JsonEscape.escapeJson(var1);
    }
}
