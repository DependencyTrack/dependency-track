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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.parser.vulndb;

import oauth.signpost.OAuthConsumer;
import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.exception.OAuthCommunicationException;
import oauth.signpost.exception.OAuthExpectationFailedException;
import oauth.signpost.exception.OAuthMessageSignerException;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.parser.vulndb.model.Results;
import org.dependencytrack.parser.vulndb.model.Vulnerability;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/*
 * Util class needed by VulnDBAnalysis Task to get vulnerabilities by the cpe provided. The result obtained from the api
 * call are parsed and processed before being returned . Class brought over from the vulndb-data-mirror repo:
 * <a href="https://github.com/stevespringett/vulndb-data-mirror">...</a> and refactored to use the apache http client
 * instead of the Unirest client it was using in the source repo.
 */
public class VulnDbClient {

    private final String consumerKey;
    private final String consumerSecret;

    private final String apiBaseUrl;


    public VulnDbClient(String consumerKey, String consumerSecret, String apiBaseUrl) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
        this.apiBaseUrl = apiBaseUrl;
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnDbClient.class);

    public Results getVulnerabilitiesByCpe(String cpe, int size, int page) throws IOException, OAuthMessageSignerException, OAuthExpectationFailedException, URISyntaxException, OAuthCommunicationException {
        String encodedCpe = cpe;

        try {
            encodedCpe = URLEncoder.encode(cpe, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException var6) {
            LOGGER.warn("An error occurred while URL encoding a CPE", var6);
            throw new UnsupportedEncodingException();
        }

        return this.getResults(apiBaseUrl + "/api/v1/vulnerabilities/find_by_cpe?&cpe=" + encodedCpe, Vulnerability.class, size, page);
    }

    private Results getResults(String url, Class clazz, int size, int page) throws IOException,
            OAuthMessageSignerException, OAuthExpectationFailedException, URISyntaxException,
            OAuthCommunicationException {
        String modifiedUrl = url.contains("?") ? url + "&" : url + "?";
        try (CloseableHttpResponse response = this.makeRequest(modifiedUrl + "size=" + size + "&page=" + page)) {
            VulnDbParser vulnDbParser = new VulnDbParser();
            Results results;
            if (response != null) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    var jsonObject = new JSONObject(responseString);
                    results = vulnDbParser.parse(jsonObject, clazz);
                    return results;
                } else {
                    results = new Results();
                    results.setErrorCondition("An unexpected response was returned from VulnDB. Request unsuccessful: " + response.getStatusLine().getStatusCode() + " - " + response.getStatusLine().getReasonPhrase());
                    this.logHttpResponseError(response);
                    return results;
                }
            } else {
                results = new Results();
                results.setErrorCondition("No response was returned from VulnDB. No further information is available.");
                return results;
            }
        }
    }

    private CloseableHttpResponse makeRequest(String url) throws OAuthMessageSignerException, OAuthExpectationFailedException, IOException, URISyntaxException, OAuthCommunicationException {
        OAuthConsumer consumer = new DefaultOAuthConsumer(this.consumerKey, this.consumerSecret);
        String signed = consumer.sign(url);
        URIBuilder uriBuilder = new URIBuilder(signed);
        HttpGet request = new HttpGet(uriBuilder.build().toString());
        request.addHeader("X-User-Agent", "Dependency Track (https://github.com/DependencyTrack/dependency-track)");
        return HttpClientPool.getClient().execute(request);
    }

    private void logHttpResponseError(CloseableHttpResponse response) {
        LOGGER.error("Response was not successful: " + response.getStatusLine().getStatusCode() + " - " + response.getStatusLine().getReasonPhrase());
    }
}
