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
package org.dependencytrack.support.config.source.memory;

import io.smallrye.config.ExpressionConfigSourceInterceptor;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class MemoryConfigSourceTest {

    @Test
    void test() {
        final SmallRyeConfig config = new SmallRyeConfigBuilder()
                .withSources(new MemoryConfigSource())
                .withInterceptors(new ExpressionConfigSourceInterceptor())
                .build();

        assertNull(config.getOptionalValue("foo.bar", String.class).orElse(null));

        MemoryConfigSource.setProperty("foo.bar", "baz");
        MemoryConfigSource.setProperty("oof.rab", "${foo.bar}");
        assertEquals("baz", config.getValue("foo.bar", String.class));
        assertEquals("baz", config.getValue("oof.rab", String.class));

        MemoryConfigSource.clear();
        assertNull(config.getOptionalValue("foo.bar", String.class).orElse(null));
        assertNull(config.getOptionalValue("oof.rab", String.class).orElse(null));
    }

}