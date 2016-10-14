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
package org.owasp.dependencytrack.auth;

import org.owasp.dependencytrack.logging.Logger;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.security.Key;
import java.security.Principal;
import java.util.Calendar;
import java.util.Date;

/**
 * Decouples the general usage of JSON Web Tokens with the actual implementation of a JWT library
 * All JWT usages should only go through this class and hide the actual implementation details
 */
public class JsonWebToken {

    private static final Logger logger = Logger.getLogger(JsonWebToken.class);

    private Key key;
    private String subject;
    private Date expiration;

    public JsonWebToken(Key key) {
        this.key = key;
    }

    public String createToken(Principal principal) {
        Date today = new Date();
        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setSubject(principal.getName());
        jwtBuilder.setIssuer("Dependency-Track");
        jwtBuilder.setIssuedAt(today);
        jwtBuilder.setExpiration(addDays(today, 7));
        return jwtBuilder.signWith(SignatureAlgorithm.HS256, key).compact();
    }

    public boolean validateToken(String token) {
        try {
            JwtParser jwtParser = Jwts.parser().setSigningKey(key);
            jwtParser.parse(token);
            this.subject = jwtParser.parseClaimsJws(token).getBody().getSubject();
            this.expiration = jwtParser.parseClaimsJws(token).getBody().getExpiration();
            return true;
        } catch (SignatureException e) {
            logger.info("Received token that did not pass signature verification");
        } catch (ExpiredJwtException e) {
            logger.debug("Received expired token");
        } catch (MalformedJwtException e) {
            logger.debug("Received malformed token");
            logger.debug(e.getMessage());
        } catch (UnsupportedJwtException | IllegalArgumentException e) {
            logger.error(e.getMessage());
        }
        return false;
    }

    /**
     * Strips the signature off the token and returns the value for the specified claim.
     * This is an unsafe method and should be used with extreme caution.
     *
     * @param token the JWT token to parse
     * @param claim the claim to retrieve
     * @return the value of the claim
     */
    public static Object parse(String token, String claim) {
        if (Jwts.parser().isSigned(token)) {
            token = token.substring(0, token.lastIndexOf(".") + 1);
        }
        return Jwts.parser().parseClaimsJwt(token).getBody().get(claim);
    }

    /**
     * Create a new future Date from the specified Date
     *
     * @param date The date to base the future date from
     * @param days The number of dates to + offset
     * @return a future date
     */
    private Date addDays(Date date, int days) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.DATE, days); //minus number would decrement the days
        return cal.getTime();
    }

    public String getSubject() {
        return subject;
    }

    public Date getExpiration() {
        return expiration;
    }

}