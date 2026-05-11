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
package org.dependencytrack.dex;

/**
 * @since 5.0.0
 */
public final class DexWorkflowLabels {

    public static final String WF_LABEL_BOM_UPLOAD_TOKEN = "bom_upload_token";
    public static final String WF_LABEL_PROJECT_UUID = "project_uuid";
    public static final String WF_LABEL_TRIGGERED_BY = "triggered_by";
    public static final String WF_LABEL_VEX_UPLOAD_TOKEN = "vex_upload_token";

    private DexWorkflowLabels() {
    }

}
