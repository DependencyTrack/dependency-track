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
package org.dependencytrack.exception;

import org.junit.Assert;
import org.junit.Test;
import java.io.IOException;

public class ParseExceptionTest {

    @Test
    public void testMessageConstructor() {
        ParseException ex = new ParseException("An error occurred");
        Assert.assertEquals("An error occurred", ex.getMessage());
    }

    @Test
    public void testThrowableConstructor() {
        IOException e = new IOException("Filed to open file");
        ParseException ex = new ParseException(e);
        Assert.assertNotNull(ex.getMessage());
        Assert.assertEquals(e, ex.getCause());
    }

    @Test
    public void testMessageThrowableConstructor() {
        IOException e = new IOException("Filed to open file");
        ParseException ex = new ParseException("Oops", e);
        Assert.assertEquals("Oops", ex.getMessage());
        Assert.assertEquals(e, ex.getCause());
    }
}
