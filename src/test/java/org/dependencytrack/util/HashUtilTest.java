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
package org.dependencytrack.util;

import org.junit.Assert;
import org.junit.Test;
import java.io.File;

public class HashUtilTest {

    @Test
    public void testMd5() throws Exception {
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("textfile.txt").getFile());
        Assert.assertEquals("6ccb8fac358fea58732ed8ffec85b9f5", HashUtil.md5(file));
    }

    @Test
    public void testSha1() throws Exception {
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("textfile.txt").getFile());
        Assert.assertEquals("3f4b24f2a4da21774622417444436b193fe34764", HashUtil.sha1(file));
    }

    @Test
    public void testSha256() throws Exception {
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("textfile.txt").getFile());
        Assert.assertEquals("958bf829329b84baef5136d99156f6703d0d95cffa9fc6cec6403ced7573eff3", HashUtil.sha256(file));
    }

    @Test
    public void testSha512() throws Exception {
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("textfile.txt").getFile());
        Assert.assertEquals("1e140d6171bf6377a749d7579034cf4879548d96e9d5299f02a5265e094168fd9812fda94fa5fa9ff45ac8454f19d18f612cb3204ad551e29baddbfa17636b59", HashUtil.sha512(file));
    }
}
