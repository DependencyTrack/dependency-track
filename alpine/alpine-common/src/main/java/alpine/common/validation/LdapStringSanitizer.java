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

import java.nio.charset.StandardCharsets;

/**
 * A sanitization utility which creates safe ldap search strings.
 *
 * @author Steve Springett
 * @since 1.4.0
 */
@SuppressWarnings("unused")
public class LdapStringSanitizer {

    private LdapStringSanitizer() { }

    /**
     * Escapes any special chars (RFC 4515) from a string representing a search filter assertion value.
     *
     * This method should only be applied to LDAP filter search inputs (or other filter inputs)
     * and not for full LDAP validation. For example:
     *<pre>
     * (&amp;(objectClass=groupOfUniqueNames)(uniqueMember=INPUT))
     *</pre>
     * In this case, the INPUT would need to be sanitized via this method.
     *
     * @param input The input string.
     * @return A assertion value string ready for insertion into a search filter string.
     * @since 1.4.0
     */
    public static String sanitize(final String input) {
        if(input == null) {
            return null;
        }
        final StringBuilder sb = new StringBuilder();

        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);

            if (c == '*') {
                // escape asterisk
                sb.append("\\2a");
            } else if (c == '(') {
                // escape left parenthesis
                sb.append("\\28");
            }  else if (c == ')') {
                // escape right parenthesis
                sb.append("\\29");
            } else if (c == '\\') {
                // escape backslash
                sb.append("\\5c");
            } else if (c == '\u0000') {
                // escape NULL char
                sb.append("\\00");
            } else if (c <= 0x7f) {
                // regular 1-byte UTF-8 char
                sb.append(String.valueOf(c));
            } else if (c >= 0x080) {
                // higher-order 2, 3 and 4-byte UTF-8 chars
                final byte[] utf8bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                for (final byte b : utf8bytes) {
                    sb.append(String.format("\\%02x", b));
                }
            }
        }
        return sb.toString();
    }
}
