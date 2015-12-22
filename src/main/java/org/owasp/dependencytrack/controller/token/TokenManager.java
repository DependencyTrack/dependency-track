/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.controller.token;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * A manager for the CSRF token for a given session. The {@link #getToken(HttpSession)} should used to
 * obtain the token value for the current session (and this should be the only way to obtain the token value).
 *
 * @author Eyal Lupu (original author)
 * @author Steve Springett (steve.springett@owasp.org)
 * https://github.com/eyal-lupu/eyallupu-blog/blob/master/SpringMVC-3.1-CSRF/src/main/java/com/eyallupu/blog/springmvc/controller/csrf/CSRFTokenManager.java
 */
final class TokenManager {

    /**
     * Private constructor.
     */
    private TokenManager() { }

    /**
     * The name that identifies a parameter as a token.
     */
    static final String TOKEN_PARAM_NAME = "nonce";

    /**
     * The location on the session which stores the token
     */
    private static final String TOKEN_SESSION_ATTR = "OWASP-Dependency-Track-Anti-CSRF-Token";

    /**
     * Returns the current (next) token that is stored in the session. If no token is current stored,
     * this method will first create and store a new token in the users session.
     * @param session a HttpSession object
     * @return a String representation of the token
     */
    static String getToken(HttpSession session) {
        String token = (String) session.getAttribute(TOKEN_SESSION_ATTR);
        if (null == token) {
            token = createToken(session);
        }
        return token;
    }

    /**
     * Evaluates if the token stored in the session matches the token sent with the request. If token values match,
     * the current token stored in the session will be overwritten with a new token that can be used for the next
     * post request.
     * @param request a HttpServletRequest object
     * @return true if tokens match, otherwise returns false
     */
    public static boolean isTokenValid(HttpServletRequest request) {
        final HttpSession session = request.getSession();
        final String sessionToken = getToken(session);
        if (request.getParameter(TOKEN_PARAM_NAME).equals(sessionToken)) {
            createToken(session);
            return true;
        }
        return false;
    }

    /**
     * Creates a new token and stores the value of the token in the session. First attempts to generate a
     * crypto-graphically secure (SHA-256) random token. If this fails for some reason, it will fall back
     * to a less secure, but almost as effective generation of random bytes.
     * @param session a HttpSession object
     * @return The Hex value of the token.
     */
    private static String createToken(HttpSession session) {
        String token;
        try  {
            final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            final MessageDigest sha = MessageDigest.getInstance("SHA-256");
            final byte[] randomDigest = sha.digest(
                    Integer.toString(random.nextInt()).getBytes(Charset.forName("UTF-8")));
            token = getHex(randomDigest);
        } catch (NoSuchAlgorithmException e) {
            // For some reason, an exception was thrown and we still need to return a random token.
            final SecureRandom random = new SecureRandom();
            final byte[] bytes = new byte[256];
            random.nextBytes(bytes);
            token = getHex(bytes);
        }
        synchronized (session) {
            session.setAttribute(TOKEN_SESSION_ATTR, token);
        }
        return token;
    }

    /**
     * Converts the specified bytes into Hex.
     * @param bytes The bytes to convert
     * @return a Hex representation in a String
     */
    private static String getHex(byte[] bytes) {
        final StringBuilder hex = new StringBuilder(2 * bytes.length);
        for (final byte b : bytes) {
            hex.append("0123456789ABCDEF".charAt((b & 0xF0) >> 4)).append("0123456789ABCDEF".charAt((b & 0x0F)));
        }
        return hex.toString();
    }

}
