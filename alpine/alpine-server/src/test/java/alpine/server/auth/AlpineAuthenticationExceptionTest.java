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
package alpine.server.auth;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.Principal;

public class AlpineAuthenticationExceptionTest {

    @Test
    public void causeTypeTest() {
        Assertions.assertEquals(6, AlpineAuthenticationException.CauseType.values().length);
        Assertions.assertEquals("INVALID_CREDENTIALS", AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS.name());
        Assertions.assertEquals("EXPIRED_CREDENTIALS", AlpineAuthenticationException.CauseType.EXPIRED_CREDENTIALS.name());
        Assertions.assertEquals("FORCE_PASSWORD_CHANGE", AlpineAuthenticationException.CauseType.FORCE_PASSWORD_CHANGE.name());
        Assertions.assertEquals("SUSPENDED", AlpineAuthenticationException.CauseType.SUSPENDED.name());
        Assertions.assertEquals("UNMAPPED_ACCOUNT", AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT.name());
        Assertions.assertEquals("OTHER", AlpineAuthenticationException.CauseType.OTHER.name());
    }

    @Test
    public void constructorATest() {
        AlpineAuthenticationException e = new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT);
        Assertions.assertEquals(AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT, e.getCauseType());
        Assertions.assertNull(e.getPrincipal());
    }

    @Test
    public void constructorBTest() {
        Principal p = Mockito.mock(Principal.class);
        AlpineAuthenticationException e = new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT, p);
        Assertions.assertEquals(AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT, e.getCauseType());
        Assertions.assertEquals(p, e.getPrincipal());
    }
}
