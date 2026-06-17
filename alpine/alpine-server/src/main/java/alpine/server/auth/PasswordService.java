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

import alpine.common.util.ByteUtil;
import alpine.config.AlpineConfigKeys;
import alpine.model.ManagedUser;
import org.eclipse.microprofile.config.ConfigProvider;
import org.mindrot.jbcrypt.BCrypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Alpine PasswordService that provides a secure method of hashing and validating user passwords.
 *
 * Internally, PasswordService uses a combination of SHA-512 and BCrypt for these functions.
 * The password goes through the following flow during the hashing process:
 *
 * Password » SHA-512 » BCrypt (per-user salt, default rounds: 14)
 *
 * In this flow, a user password is hashed using SHA-512 which creates a 128 character HEX
 * representation of a hash. This is called the prehash. The prehash acts to both 'extend' the
 * password and to introduce built-in denial-of-service protection from exceptionally long
 * passwords. Once the password is prehashed, it's sent to BCrypt where a per-user salt is
 * used and the password is properly hashed. Both the creation and verification of hashes go
 * through this process.
 *
 * Additionally, this class contains a method which will determine if a password should be rehashed
 * due to an increase in rounds defined on the server.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public final class PasswordService {

    private static final int ROUNDS = ConfigProvider.getConfig().getValue(AlpineConfigKeys.BCRYPT_ROUNDS, Integer.class);

    /**
     * Private constructor
     */
    private PasswordService() { }

    /**
     * Given a password to hash, this method will first prehash the password using SHA-512 thus creating
     * a 128 character HEX representation of the password, which is then sent to BCrypt where a unique
     * salt is generated and the prehashed password is properly hashed using the configured BCrypt
     * work factor (determined by {@link AlpineConfigKeys#BCRYPT_ROUNDS}.
     *
     * @param password the password to hash
     * @return a hashed password
     * @since 1.0.0
     */
    public static char[] createHash(final char[] password) {
        final char[] prehash = createSha512Hash(password);
        // Todo: remove String when Jbcrypt supports char[]
        return BCrypt.hashpw(new String(prehash), BCrypt.gensalt(ROUNDS)).toCharArray();
    }

    /**
     * Given a password to hash, this method will first prehash the password using SHA-512 thus creating
     * a 128 character HEX representation of the password, which is then sent to BCrypt where the prehashed
     * password is properly hashed using the specified salt and uses the configured BCrypt work factor
     * (determined by {@link AlpineConfigKeys#BCRYPT_ROUNDS}.
     *
     * @param password the password to hash
     * @param salt the salt to use when hashing this password
     * @return a hashed password
     * @since 1.0.0
     */
    public static char[] createHash(final char[] password, final char[] salt) {
        final char[] prehash = createSha512Hash(password);
        // Todo: remove String when Jbcrypt supports char[]
        return BCrypt.hashpw(new String(prehash), new String(salt)).toCharArray();
    }

    /**
     * Checks the validity of the asserted password against a ManagedUsers actual hashed password.
     *
     * @param assertedPassword the clear text password to check
     * @param user The ManagedUser to check the password of
     * @return true if assertedPassword matches the expected password of the ManangedUser, false if not
     * @since 1.0.0
     */
    public static boolean matches(final char[] assertedPassword, final ManagedUser user) {
        final char[] prehash = createSha512Hash(assertedPassword);
        // Todo: remove String when Jbcrypt supports char[]
        return BCrypt.checkpw(new String(prehash), user.getPassword());
    }

    /**
     * Checks the asserted BCrypt formatted hashed password and determines if the password should
     * be rehashed or not. If the BCrypt work factor is increased (from 12 to 14 for example),
     * passwords should be evaluated and if the existing stored hash uses a work factor less than
     * what is configured, then the bcryptHash should be rehashed. The same does not apply in
     * reverse. Stored hashed passwords with a work factor greater than the configured work factor
     * will return false, meaning they should not be rehashed.
     *
     * If the bcryptHash length is less than the minimum length of a BCrypt hash, this method
     * will return true.
     *
     * @param bcryptHash the hashed BCrypt to check
     * @return true if the password should be rehashed, false if not
     * @since 1.0.0
     */
    public static boolean shouldRehash(final char[] bcryptHash) {
        int rounds;
        if (bcryptHash.length < 59) {
            return true;
        }
        final StringBuilder sb = new StringBuilder();
        sb.append(bcryptHash[4]);
        if (bcryptHash[5] != '$') {
            sb.append(bcryptHash[5]);
        }
        rounds = Integer.valueOf(sb.toString());
        return rounds < ROUNDS;
    }

    /**
     * Creates a SHA-512 hash of the specified password and returns a HEX
     * representation of the hash. This method should NOT be used solely
     * for password hashing, but in conjunction with password-specific
     * hashing functions.
     *
     * @param password the password to hash
     * @return a char[] of the hashed password
     * @since 1.0.0
     */
    private static char[] createSha512Hash(final char[] password) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.update(ByteUtil.toBytes(password));
            final byte[] byteData = digest.digest();

            final StringBuilder sb = new StringBuilder();
            for (final byte data : byteData) {
                sb.append(Integer.toString((data & 0xff) + 0x100, 16).substring(1));
            }
            final char[] hash = new char[128];
            sb.getChars(0, sb.length(), hash, 0);
            return hash;
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

}
