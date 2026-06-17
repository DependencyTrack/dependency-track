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

public class LdapStringSanitizerTest {

    @Test
    public void sanitizeTest() {
        Assertions.assertEquals("abc\\2adef", LdapStringSanitizer.sanitize("abc*def"));
        Assertions.assertEquals("abc\\28def", LdapStringSanitizer.sanitize("abc(def"));
        Assertions.assertEquals("abc\\29def", LdapStringSanitizer.sanitize("abc)def"));
        Assertions.assertEquals("abc\\5cdef", LdapStringSanitizer.sanitize("abc\\def"));
        Assertions.assertEquals("abc\\00def", LdapStringSanitizer.sanitize("abc\u0000def"));
        Assertions.assertEquals("abc\\c9\\86def", LdapStringSanitizer.sanitize("abc\u0246def"));
    }
}
