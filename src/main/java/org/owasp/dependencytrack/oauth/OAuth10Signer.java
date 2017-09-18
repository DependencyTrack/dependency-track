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
package org.owasp.dependencytrack.oauth;

import alpine.Config;
import org.apache.commons.collections.KeyValue;
import org.apache.commons.collections.keyvalue.DefaultKeyValue;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * This class provides the absolute minimum requirements to sign and create an OAuth 1.0a
 * Authentication header with the goal of not introducing unnecessary dependencies.
 */
public class OAuth10Signer {

    private static final String ENCODING = "UTF-8";
    private static final String HMAC_SHA1 = "HmacSHA1";
    private static final String USER_AGENT = Config.getInstance().getProperty(
            Config.AlpineKey.APPLICATION_NAME
                    + " v" + Config.AlpineKey.APPLICATION_VERSION
                    + " (" + Config.AlpineKey.APPLICATION_TIMESTAMP + ")");

    private String consumerKey;
    private String consumerSecret;

    public OAuth10Signer(String consumerKey, String consumerSecret) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
    }

    private String sign(String url, String params)
            throws UnsupportedEncodingException, NoSuchAlgorithmException,
            InvalidKeyException {

        final StringBuilder sb = new StringBuilder();
        sb.append("GET&");
        sb.append(url);
        sb.append("&");
        sb.append(params);

        final byte[] keyBytes = (consumerSecret + "&").getBytes(ENCODING);
        final SecretKey key = new SecretKeySpec(keyBytes, HMAC_SHA1);
        final Mac mac = Mac.getInstance(HMAC_SHA1);
        mac.init(key);

        return new String(Base64.getEncoder().encode(mac.doFinal(sb.toString().getBytes(ENCODING))), ENCODING).trim();
    }

    public String getAuthorizationHeader(String url)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        final List<KeyValue> pairs = new ArrayList<>();
        pairs.add(new DefaultKeyValue("oauth_consumer_key", consumerKey));
        pairs.add(new DefaultKeyValue("oauth_nonce", UUID.randomUUID().toString().replace("-", "")));
        pairs.add(new DefaultKeyValue("oauth_signature_method", "HMAC-SHA1"));
        pairs.add(new DefaultKeyValue("oauth_timestamp", (System.currentTimeMillis() / 1000)));
        pairs.add(new DefaultKeyValue("oauth_version", "1.0"));

        // generate the oauth_signature
        final String signature = sign(
                URLEncoder.encode(url, ENCODING),
                URLEncoder.encode(urlFormat(pairs), ENCODING)
        );

        // insert the signature into the pairs
        pairs.add(2, new DefaultKeyValue("oauth_signature", URLEncoder.encode(signature, ENCODING)));
        return flatten(pairs);
    }

    public Map<String, String> getAuthorizationHeaders(String url)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        final Map<String, String> map = new HashMap<>();
        map.put("Authorization", getAuthorizationHeader(url));
        map.put("User-Agent", USER_AGENT);
        map.put("X-User-Agent", USER_AGENT);
        return map;
    }

    private String flatten(List<KeyValue> pairs) {
        final StringBuilder sb = new StringBuilder();
        sb.append("OAuth").append(" ");
        for (int i = 0; i < pairs.size(); i++) {
            sb.append(pairs.get(i).getKey()).append("=");
            sb.append("\"").append(pairs.get(i).getValue()).append("\"");
            if (i + 1 < pairs.size()) {
                sb.append(", ");
            }
        }
        return sb.toString();
    }

    private String urlFormat(List<KeyValue> pairs) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pairs.size(); i++) {
            sb.append(pairs.get(i).getKey()).append("=").append(pairs.get(i).getValue());
            if (i + 1 < pairs.size()) {
                sb.append("&");
            }
        }
        return sb.toString();
    }
}
