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
package org.dependencytrack.util;

import javax.json.JsonObjectBuilder;
import java.math.BigDecimal;
import java.math.BigInteger;

public class JsonUtil {

    /**
     * Private constructor.
     */
    public JsonUtil() { }

    public static JsonObjectBuilder add(JsonObjectBuilder builder, String key, String value) {
        if (value != null) {
            builder.add(key, value);
        }
        return builder;
    }

    public static JsonObjectBuilder add(JsonObjectBuilder builder, String key, BigInteger value) {
        if (value != null) {
            builder.add(key, value);
        }
        return builder;
    }

    public static JsonObjectBuilder add(JsonObjectBuilder builder, String key, BigDecimal value) {
        if (value != null) {
            builder.add(key, value);
        }
        return builder;
    }

    public static JsonObjectBuilder add(JsonObjectBuilder builder, String key, Enum value) {
        if (value != null) {
            builder.add(key, value.name());
        }
        return builder;
    }

}
