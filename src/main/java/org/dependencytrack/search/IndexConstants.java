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
package org.dependencytrack.search;

import java.util.HashMap;
import java.util.Map;

/**
 * Helper class that defines constants used by the indexers.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class IndexConstants {

    static final String PROJECT_UUID = "uuid";
    static final String PROJECT_NAME = "name";
    static final String PROJECT_VERSION = "version";
    static final String PROJECT_PROPERTIES = "properties";
    static final String PROJECT_DESCRIPTION = "description";
    static final String[] PROJECT_SEARCH_FIELDS = {
            PROJECT_UUID, PROJECT_NAME, PROJECT_VERSION, PROJECT_PROPERTIES, PROJECT_DESCRIPTION
    };

    static final String COMPONENT_UUID = "uuid";
    static final String COMPONENT_NAME = "name";
    static final String COMPONENT_GROUP = "group";
    static final String COMPONENT_VERSION = "version";
    static final String COMPONENT_SHA1 = "sha1";
    static final String COMPONENT_DESCRIPTION = "description";
    static final String[] COMPONENT_SEARCH_FIELDS = {
            COMPONENT_UUID, COMPONENT_NAME, COMPONENT_GROUP, COMPONENT_VERSION, COMPONENT_SHA1, COMPONENT_DESCRIPTION
    };

    static final String SERVICECOMPONENT_UUID = "uuid";
    static final String SERVICECOMPONENT_NAME = "name";
    static final String SERVICECOMPONENT_GROUP = "group";
    static final String SERVICECOMPONENT_VERSION = "version";
    static final String SERVICECOMPONENT_URL = "url";
    static final String SERVICECOMPONENT_DESCRIPTION = "description";
    static final String[] SERVICECOMPONENT_SEARCH_FIELDS = {
            SERVICECOMPONENT_UUID, SERVICECOMPONENT_NAME, SERVICECOMPONENT_GROUP, SERVICECOMPONENT_VERSION, SERVICECOMPONENT_URL, SERVICECOMPONENT_DESCRIPTION
    };

    static final String VULNERABILITY_UUID = "uuid";
    static final String VULNERABILITY_VULNID = "vulnId";
    static final String VULNERABILITY_SOURCE = "source";
    static final String VULNERABILITY_DESCRIPTION = "description";
    static final String[] VULNERABILITY_SEARCH_FIELDS = {
            VULNERABILITY_UUID, VULNERABILITY_VULNID, VULNERABILITY_DESCRIPTION
    };

    static final String LICENSE_UUID = "uuid";
    static final String LICENSE_LICENSEID = "licenseId";
    static final String LICENSE_NAME = "name";
    static final String[] LICENSE_SEARCH_FIELDS = {
            LICENSE_UUID, LICENSE_LICENSEID, LICENSE_NAME
    };

    static final String CPE_UUID = "uuid";
    static final String CPE_22 = "cpe22";
    static final String CPE_23 = "cpe23";
    static final String CPE_VENDOR = "vendor";
    static final String CPE_PRODUCT = "product";
    static final String CPE_VERSION = "version";
    static final String[] CPE_SEARCH_FIELDS = {
            CPE_22, CPE_23, CPE_VENDOR, CPE_PRODUCT, CPE_VERSION
    };

    static final String VULNERABLESOFTWARE_UUID = "uuid";
    static final String VULNERABLESOFTWARE_CPE_22 = "cpe22";
    static final String VULNERABLESOFTWARE_CPE_23 = "cpe23";
    static final String VULNERABLESOFTWARE_VENDOR = "vendor";
    static final String VULNERABLESOFTWARE_PRODUCT = "product";
    static final String VULNERABLESOFTWARE_VERSION = "version";
    static final String[] VULNERABLESOFTWARE_SEARCH_FIELDS = {
            VULNERABLESOFTWARE_CPE_22, VULNERABLESOFTWARE_CPE_23, VULNERABLESOFTWARE_VENDOR,
            VULNERABLESOFTWARE_PRODUCT, VULNERABLESOFTWARE_VERSION
    };

    /**
     * Field constants highlighting boost factors in performing search
     * for various user-defined fields.
     * = 1.0 indicates uniform boost (equal weightage)
     * > 1.0 indicates over-boost (higher weightage)
     * < 1.0 indicates under-boost (lower weightage)
     */
    private static final float BOOST_PROJECT_UUID = 100.0f;
    private static final float BOOST_PROJECT_NAME = 50.0f;
    private static final float BOOST_PROJECT_VERSION = 10.0f;
    private static final float BOOST_PROJECT_PROPERTIESC = 30.0f;
    private static final float BOOST_PROJECT_DESCRIPTION = 20.0f;

    private static final float BOOST_COMPONENT_UUID = 100.0f;
    private static final float BOOST_COMPONENT_NAME = 50.0f;
    private static final float BOOST_COMPONENT_GROUP = 60.0f;
    private static final float BOOST_COMPONENT_VERSION = 10.0f;
    private static final float BOOST_COMPONENT_SHA1 = 90.0f;
    private static final float BOOST_COMPONENT_DESCRIPTION = 20.0f;

    private static final float BOOST_SERVICECOMPONENT_UUID = 100.0f;
    private static final float BOOST_SERVICECOMPONENT_NAME = 50.0f;
    private static final float BOOST_SERVICECOMPONENT_GROUP = 60.0f;
    private static final float BOOST_SERVICECOMPONENT_VERSION = 10.0f;
    private static final float BOOST_SERVICECOMPONENT_URL = 90.0f;
    private static final float BOOST_SERVICECOMPONENT_DESCRIPTION = 20.0f;

    private static final float BOOST_VULNERABILITY_UUID = 100.0f;
    private static final float BOOST_VULNERABILITY_VULNID = 90.0f;
    private static final float BOOST_VULNERABILITY_DESCRIPTION = 20.0f;

    private static final float BOOST_LICENSE_UUID = 100.0f;
    private static final float BOOST_LICENSE_LICENSEID = 90.0f;
    private static final float BOOST_LICENSE_NAME = 20.0f;

    private static final float BOOST_CPE_UUID = 100.0f;
    private static final float BOOST_CPE_22 = 90.0f;
    private static final float BOOST_CPE_23 = 90.0f;
    private static final float BOOST_CPE_VENDOR = 20.0f;
    private static final float BOOST_CPE_PRODUCT = 20.0f;

    private static final float BOOST_VULNERABLESOFTWARE_UUID = 100.0f;
    private static final float BOOST_VULNERABLESOFTWARE_CPE_22 = 90.0f;
    private static final float BOOST_VULNERABLESOFTWARE_CPE_23 = 90.0f;
    private static final float BOOST_VULNERABLESOFTWARE_VENDOR = 20.0f;
    private static final float BOOST_VULNERABLESOFTWARE_PRODUCT = 20.0f;

    /**
     * Private constructor.
     */
    private IndexConstants() { }

    private static Map<String, Float> searchBoosts = new HashMap<>();

    public static Map<String, Float> getBoostMap() {
        if (searchBoosts.isEmpty()) {
            searchBoosts.put(PROJECT_UUID, BOOST_PROJECT_UUID);
            searchBoosts.put(PROJECT_NAME, BOOST_PROJECT_NAME);
            searchBoosts.put(PROJECT_VERSION, BOOST_PROJECT_VERSION);
            searchBoosts.put(PROJECT_PROPERTIES, BOOST_PROJECT_PROPERTIESC);
            searchBoosts.put(PROJECT_DESCRIPTION, BOOST_PROJECT_DESCRIPTION);

            searchBoosts.put(COMPONENT_UUID, BOOST_COMPONENT_UUID);
            searchBoosts.put(COMPONENT_NAME, BOOST_COMPONENT_NAME);
            searchBoosts.put(COMPONENT_GROUP, BOOST_COMPONENT_GROUP);
            searchBoosts.put(COMPONENT_VERSION, BOOST_COMPONENT_VERSION);
            searchBoosts.put(COMPONENT_SHA1, BOOST_COMPONENT_SHA1);
            searchBoosts.put(COMPONENT_DESCRIPTION, BOOST_COMPONENT_DESCRIPTION);

            searchBoosts.put(VULNERABILITY_UUID, BOOST_VULNERABILITY_UUID);
            searchBoosts.put(VULNERABILITY_VULNID, BOOST_VULNERABILITY_VULNID);
            searchBoosts.put(VULNERABILITY_DESCRIPTION, BOOST_VULNERABILITY_DESCRIPTION);

            searchBoosts.put(LICENSE_UUID, BOOST_LICENSE_UUID);
            searchBoosts.put(LICENSE_LICENSEID, BOOST_LICENSE_LICENSEID);
            searchBoosts.put(LICENSE_NAME, BOOST_LICENSE_NAME);

            searchBoosts.put(CPE_UUID, BOOST_CPE_UUID);
            searchBoosts.put(CPE_22, BOOST_CPE_22);
            searchBoosts.put(CPE_23, BOOST_CPE_23);
            searchBoosts.put(CPE_VENDOR, BOOST_CPE_VENDOR);
            searchBoosts.put(CPE_PRODUCT, BOOST_CPE_PRODUCT);

            searchBoosts.put(VULNERABLESOFTWARE_UUID, BOOST_VULNERABLESOFTWARE_UUID);
            searchBoosts.put(VULNERABLESOFTWARE_CPE_22, BOOST_VULNERABLESOFTWARE_CPE_22);
            searchBoosts.put(VULNERABLESOFTWARE_CPE_23, BOOST_VULNERABLESOFTWARE_CPE_23);
            searchBoosts.put(VULNERABLESOFTWARE_VENDOR, BOOST_VULNERABLESOFTWARE_VENDOR);
            searchBoosts.put(VULNERABLESOFTWARE_PRODUCT, BOOST_VULNERABLESOFTWARE_PRODUCT);
        }
        return searchBoosts;
    }
}
