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
package org.dependencytrack.integration;

import org.junit.Test;
import java.io.File;
import java.util.UUID;

public class PopulateData {

    private static final String BASE_URL = "http://localhost:8080";
    private static final String API_KEY = "hETzpWanQkXV6KsJsfPuFoNBRZdiiDyY";

    @Test
    public void doit() throws Exception {
        ApiClient api = new ApiClient(BASE_URL, API_KEY);
        UUID uuid = api.createProject("SonarQube", "5.6");

        File file = new File(this.getClass().getResource("/integration/sonarqube-6.5.spdx").getFile());

        if (file.exists()) {
            System.out.println("Found It");
            api.uploadBom(uuid, file);
        }

    }


    public static void main(String[] args) throws Exception {
        final PopulateData populateData = new PopulateData();
        populateData.doit();
    }
}
