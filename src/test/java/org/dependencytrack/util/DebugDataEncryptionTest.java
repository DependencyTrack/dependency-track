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

import alpine.security.crypto.DataEncryption;
import alpine.security.crypto.KeyManager;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

public class DebugDataEncryptionTest {

    @Test
    public void testReloadAndRetry() throws Exception {
        final Field secretKeyField = KeyManager.class.getDeclaredField("secretKey");
        secretKeyField.setAccessible(true);

        // Encrypt a value with KeyManager's current secret key.
        final String encryptedValue = DataEncryption.encryptAsString("foobarbaz");

        // Generate a new secret key and replace KeyManager's current key with it.
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.init(256, random);
        final SecretKey newSecretKey = keyGen.generateKey();
        secretKeyField.set(KeyManager.getInstance(), newSecretKey);

        // Decrypt the value. This should work due to DebugDataEncryption
        // reloading the secret key from disk upon decryption failure.
        final String decryptedValue = DebugDataEncryption.decryptAsString(encryptedValue);
        assertThat(decryptedValue).isEqualTo("foobarbaz");
    }


}