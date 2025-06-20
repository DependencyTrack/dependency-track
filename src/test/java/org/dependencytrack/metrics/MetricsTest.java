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
package org.dependencytrack.metrics;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class MetricsTest {

    @Test
    void testMetricCalculations() {
        double chml = Metrics.inheritedRiskScore(20, 10, 5, 1, 3);
        Assertions.assertEquals(281, chml, 0);

        double ratio = Metrics.vulnerableComponentRatio(5, 100);
        Assertions.assertEquals(0.05, ratio, 0);
    }
}
