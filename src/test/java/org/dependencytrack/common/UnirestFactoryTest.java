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
package org.dependencytrack.common;

import kong.unirest.UnirestInstance;
import org.junit.Assert;
import org.junit.Test;

public class UnirestFactoryTest {

    @Test
    public void instanceTest() {
        UnirestInstance ui1 = UnirestFactory.getUnirestInstance();
        UnirestInstance ui2 = UnirestFactory.getUnirestInstance();
        Assert.assertSame(ui1, ui2);
    }

    @Test
    public void httpClientTest() {
        UnirestInstance ui = UnirestFactory.getUnirestInstance();
        Assert.assertNotSame(ui.config().getClient().getClient(), ManagedHttpClientFactory.newManagedHttpClient());
    }
}
