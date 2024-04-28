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

import alpine.common.logging.Logger;
import alpine.security.crypto.DataEncryption;
import alpine.security.crypto.KeyManager;
import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.BadPaddingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @since 4.11.0
 */
public class DebugDataEncryption {

    private static final Logger LOGGER = Logger.getLogger(DataEncryption.class);
    private static final ReentrantLock RELOAD_LOCK = new ReentrantLock();

    /**
     * Wrapper around {@link DataEncryption#decryptAsString(String)} to help with debugging
     * and / or handling of {@link BadPaddingException}s some users are experiencing.
     *
     * @param encryptedText the text to decrypt
     * @return the decrypted string
     * @throws Exception a number of exceptions may be thrown
     * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/265">Issue 265</a>
     * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/2366">Issue 2366</a>
     * @see <a href="https://owasp.slack.com/archives/C6R3R32H4/p1713945310408209">Slack Thread</a>
     * @see DataEncryption#decryptAsString(String)
     */
    public static String decryptAsString(final String encryptedText) throws Exception {
        return retryDecryptAsString(encryptedText, 0);
    }

    private static String retryDecryptAsString(final String encryptedText, final int attempt) throws Exception {
        try {
            return DataEncryption.decryptAsString(encryptedText);
        } catch (BadPaddingException e) {
            final byte[] currentKey = KeyManager.getInstance().getSecretKey().getEncoded();

            RELOAD_LOCK.lock();
            try {
                reloadKeys();
            } catch (NoSuchFieldException | NoSuchMethodException | InvocationTargetException
                     | IllegalAccessException | RuntimeException ex) {
                LOGGER.warn("Failed to reload keys while handling %s".formatted(e), ex);
                throw e;
            } finally {
                RELOAD_LOCK.unlock();
            }

            final byte[] reloadedKey = KeyManager.getInstance().getSecretKey().getEncoded();
            final boolean isKeyDifferent = !Arrays.equals(currentKey, reloadedKey);

            if (isKeyDifferent && attempt < 1) {
                LOGGER.warn("""
                        Failed to decrypt value, possibly because the secret key in memory got corrupted. \
                        Reloaded key from disk and detected it being different from the previously loaded key. \
                        Please report this to https://github.com/DependencyTrack/dependency-track/issues/2366 \
                        so the root cause can be identified. Additional information about the keys: \
                        length{previous=%d, reloaded=%d}, sha256={previous=%s, reloaded=%s}"""
                        .formatted(currentKey.length, reloadedKey.length, DigestUtils.sha256Hex(currentKey), DigestUtils.sha256Hex(reloadedKey)));
                return retryDecryptAsString(encryptedText, attempt + 1);
            } else if (!isKeyDifferent) {
                LOGGER.warn("""
                        Failed to decrypt value, possibly because it has been encrypted with a different key, \
                        or the encrypted value is corrupted. To verify the latter, please check the respective \
                        value in the database. For comparison, the base64-encoded value for which decryption \
                        was attempted has a length of %d, and a sha256 digest of %s. If this is different to what's \
                        stored in your database, please report this to https://github.com/DependencyTrack/dependency-track/issues/2366, \
                        so the root cause can be identified.""".formatted(encryptedText.length(), DigestUtils.sha256Hex(encryptedText)));
            }

            throw e;
        }
    }

    private static void reloadKeys() throws NoSuchFieldException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        final Field secretKeyField = KeyManager.class.getDeclaredField("secretKey");
        secretKeyField.setAccessible(true);

        final Method loadMethod = KeyManager.class.getDeclaredMethod("initialize");
        loadMethod.setAccessible(true);

        secretKeyField.set(KeyManager.getInstance(), null);
        loadMethod.invoke(KeyManager.getInstance());
    }

}
