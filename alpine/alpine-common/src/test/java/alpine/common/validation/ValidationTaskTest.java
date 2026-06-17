/*
 * This file is part of Alpine.
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
package alpine.common.validation;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

public class ValidationTaskTest {

    @Test
    public void constructorATest() {
        Pattern p = Pattern.compile("[A-Za-z]");
        ValidationTask task = new ValidationTask(p, "Test Input", "Invalid", true);
        Assertions.assertEquals(p, task.getPattern());
        Assertions.assertEquals("Test Input", task.getInput());
        Assertions.assertEquals("Invalid", task.getErrorMessage());
        Assertions.assertTrue(task.isRequired());
    }

    @Test
    public void constructorBTest() {
        Pattern p = Pattern.compile("[A-Za-z]");
        ValidationTask task = new ValidationTask(p, "Test Input", "Invalid");
        Assertions.assertEquals(p, task.getPattern());
        Assertions.assertEquals("Test Input", task.getInput());
        Assertions.assertEquals("Invalid", task.getErrorMessage());
        Assertions.assertTrue(task.isRequired());
    }
}
