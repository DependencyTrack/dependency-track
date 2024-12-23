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
package org.dependencytrack.util;

import org.junit.Assert;
import org.junit.Test;

public class HttpUtilTest {

    public void testBasicAuthHeaderValue() throws Exception {
        String authvalue = HttpUtil.basicAuthHeaderValue("username", "password");
        Assert.assertEquals("Basic dXNlcm5hbWU6cGFzc3dvcmQ=", authvalue);
    }

    @Test
    public void testBearerAuthHeader() throws Exception {
        String authvalue = HttpUtil.constructAuthHeaderValue("username", "password", "bearer_token");
        Assert.assertEquals("Bearer bearer_token", authvalue);
    }

    @Test
    public void testBasicAuthHeader() throws Exception {
        String authvalue = HttpUtil.basicAuthHeader("username", "password");
        Assert.assertEquals("Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=", authvalue);
    }

}
