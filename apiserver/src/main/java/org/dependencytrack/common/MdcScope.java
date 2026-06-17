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
package org.dependencytrack.common;

import org.slf4j.MDC;
import org.slf4j.MDC.MDCCloseable;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @since 5.0.0
 */
public class MdcScope implements Closeable {

    private final List<MDCCloseable> mdcCloseables = new ArrayList<>();

    public MdcScope(final Map<String, String> variables) {
        for (final Map.Entry<String, String> entry : variables.entrySet()) {
            if (MDC.get(entry.getKey()) == null) {
                mdcCloseables.add(MDC.putCloseable(entry.getKey(), entry.getValue()));
            }
        }
    }

    @Override
    public void close() {
        mdcCloseables.forEach(MDCCloseable::close);
    }

}
