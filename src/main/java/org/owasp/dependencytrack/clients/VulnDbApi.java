/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.clients;

import alpine.Config;
import alpine.logging.Logger;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import oauth.signpost.OAuthConsumer;
import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.exception.OAuthException;
import org.owasp.dependencytrack.DependencyTrackConfigKey;
import org.owasp.dependencytrack.parser.vulndb.VulnDbParser;
import org.owasp.dependencytrack.parser.vulndb.model.Product;
import org.owasp.dependencytrack.parser.vulndb.model.Results;
import org.owasp.dependencytrack.parser.vulndb.model.Vendor;
import org.owasp.dependencytrack.parser.vulndb.model.Version;
import org.owasp.dependencytrack.parser.vulndb.model.Vulnerability;

/**
 * OAuth access to the VulnDB API. For more information visit https://vulndb.cyberriskanalytics.com/ .
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class VulnDbApi {

    private static final Logger LOGGER = Logger.getLogger(VulnDbApi.class);
    private static final boolean ENABLED = Config.getInstance().getPropertyAsBoolean(DependencyTrackConfigKey.DATASOURCE_VULN_DB_ENABLED);
    private static final String CONSUMER_KEY = Config.getInstance().getProperty(DependencyTrackConfigKey.DATASOURCE_VULN_DB_KEY);
    private static final String CONSUMER_SECRET = Config.getInstance().getProperty(DependencyTrackConfigKey.DATASOURCE_VULN_DB_SECRET);
    private static final String VENDORS_URL = "https://vulndb.cyberriskanalytics.com/api/v1/vendors/";
    private static final String PRODUCTS_URL = "https://vulndb.cyberriskanalytics.com/api/v1/products/";
    private static final String VERSIONS_URL = "https://vulndb.cyberriskanalytics.com/api/v1/versions/by_product_id?product_id=";
    private static final String VULNERABILITIES_URL = "https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/"
            + "?nested=true&additional_info=true&show_cpe=true&show_cvss_v3=true&package_info=true&vtem=true";
    private static final String USER_AGENT = Config.getInstance().getProperty(Config.AlpineKey.APPLICATION_NAME)
            + " v" + Config.getInstance().getProperty(Config.AlpineKey.APPLICATION_VERSION)
            + " (" + Config.getInstance().getProperty(Config.AlpineKey.APPLICATION_TIMESTAMP) + ")";


    /**
     * Makes a request and returns {@link Vendor} Results.
     *
     * @param size the number of items to fetch
     * @param page the page number of the fetched items
     * @return a Results object
     * @since 3.0.0
     */
    public Results getVendors(int size, int page) {
        return getResults(VENDORS_URL, Vendor.class, size, page);
    }

    /**
     * Makes a request and returns {@link Product} Results.
     *
     * @param size the number of items to fetch
     * @param page the page number of the fetched items
     * @return a Results object
     * @since 3.0.0
     */
    public Results getProducts(int size, int page) {
        return getResults(PRODUCTS_URL, Product.class, size, page);
    }

    /**
     * Makes a request and returns {@link Version} Results.
     *
     * @param productId the VulnDB product_id to retrieve versions from
     * @param size      the number of items to fetch
     * @param page      the page number of the fetched items
     * @return a Results object
     * @since 3.0.0
     */
    public Results getVersions(int productId, int size, int page) {
        return getResults(VERSIONS_URL + productId, Version.class, size, page);
    }

    /**
     * Makes a request and returns {@link Vulnerability} Results.
     *
     * @param size the number of items to fetch
     * @param page the page number of the fetched items
     * @return a Results object
     * @since 3.0.0
     */
    public Results getVulnerabilities(int size, int page) {
        return getResults(VULNERABILITIES_URL, Vulnerability.class, size, page);
    }

    /**
     * Makes a request and returns the results
     *
     * @param url   the URL being requested
     * @param clazz the model vulndb model class to parse
     * @param size  the number of items to fetch
     * @param page  the page number of the fetched items
     * @return a parsed Results object
     * @since 3.0.0
     */
    private Results getResults(String url, Class clazz, int size, int page) {
        url = (url.contains("?")) ? url + "&" : url + "?";
        final HttpResponse<JsonNode> response = makeRequest(url + "size=" + size + "&page=" + page);
        if (response != null) {
            if (response.getStatus() == 200) {
                final VulnDbParser parser = new VulnDbParser();
                return parser.parse(response.getBody(), clazz);
            } else {
                LOGGER.error("Response was not successful: " + response.getStatus() + " - " + response.getStatusText());
            }
        }
        return new Results();
    }

    /**
     * Makes a one-legged OAuth 1.0a request for the specified URL.
     *
     * @param url the URL being requested
     * @return an HttpResponse
     * @since 3.0.0
     */
    private HttpResponse<JsonNode> makeRequest(String url) {
        if (ENABLED) {
            try {
                final OAuthConsumer consumer = new DefaultOAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET);
                final String signed = consumer.sign(url);
                return Unirest.get(signed).header("User-Agent", USER_AGENT).header("X-User-Agent", USER_AGENT).asJson();
            } catch (OAuthException | UnirestException e) {
                LOGGER.error("An error occurred making request: " + url, e);
            }
        }
        return null;
    }
}
