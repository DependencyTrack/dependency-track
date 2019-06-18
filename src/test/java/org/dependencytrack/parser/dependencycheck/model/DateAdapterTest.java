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

package org.dependencytrack.parser.dependencycheck.model;

import org.junit.Assert;
import org.junit.Test;
import org.dependencytrack.PersistenceCapableTest;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

public class DateAdapterTest extends PersistenceCapableTest {

    @Test
    public void parseTest() throws Exception {
        DateAdapter adapter = new DateAdapter();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        sdf.setTimeZone(TimeZone.getTimeZone("GMT"));

        Assert.assertEquals(
            "2017-09-08T07:28:27.566+0000",
            sdf.format(adapter.unmarshal("2017-09-08T00:28:27.566-0700")));
        Assert.assertEquals(
            "2017-09-08T00:28:27.566+0000",
            sdf.format(adapter.unmarshal("2017-09-08T00:28:27.566Z")));
    }
}
