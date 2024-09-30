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

/**
 * Common fields for use with SLF4J's {@link org.slf4j.MDC}.
 *
 * @since 4.11.0
 */
public final class MdcKeys {

    public static final String MDC_BOM_FORMAT = "bomFormat";
    public static final String MDC_BOM_SERIAL_NUMBER = "bomSerialNumber";
    public static final String MDC_BOM_SPEC_VERSION = "bomSpecVersion";
    public static final String MDC_BOM_UPLOAD_TOKEN = "bomUploadToken";
    public static final String MDC_BOM_VERSION = "bomVersion";
    public static final String MDC_EVENT_TOKEN = "eventToken";
    public static final String MDC_PROJECT_NAME = "projectName";
    public static final String MDC_PROJECT_UUID = "projectUuid";
    public static final String MDC_PROJECT_VERSION = "projectVersion";

    private MdcKeys() {
    }

}
