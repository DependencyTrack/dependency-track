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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package alpine.security.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.cert.X509Certificate;

public class RelaxedX509TrustManagerTest {

    @Test
    public void basicTest() throws Exception {
        RelaxedX509TrustManager trustManager = new RelaxedX509TrustManager();
        Assertions.assertNull(trustManager.getAcceptedIssuers());
        X509Certificate[] certs = {Mockito.mock(X509Certificate.class)};
        trustManager.checkClientTrusted(certs, null);
        trustManager.checkServerTrusted(certs, null);
    }
}
