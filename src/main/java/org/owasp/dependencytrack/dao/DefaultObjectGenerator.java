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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */

package org.owasp.dependencytrack.dao;

import org.apache.commons.io.IOUtils;
import org.hibernate.Hibernate;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Roles;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Blob;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class DefaultObjectGenerator implements ApplicationListener<ContextRefreshedEvent> {

    /**
     * Setup logger
     */
    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(DefaultObjectGenerator.class);

    /**
     * Specify default license names and files
     */
    private static final LinkedHashMap<String, String> LICENSES;
    static {
        LICENSES = new LinkedHashMap<String, String>();
        LICENSES.put("Apache License 1.0", "licenses/Apache/LICENSE-1.0.txt");
        LICENSES.put("Apache License 1.1", "licenses/Apache/LICENSE-1.1.txt");
        LICENSES.put("Apache License 2.0", "licenses/Apache/LICENSE-2.0.txt");
        LICENSES.put("BSD License - Original (4 Clause)", "licenses/BSD/bsd-original-4clause.txt");
        LICENSES.put("BSD License - Revised (3 Clause)", "licenses/BSD/bsd-revised-3clause.txt");
        LICENSES.put("BSD License - Simplified (2 Clause)", "licenses/BSD/bsd-simplified-2clause.txt");
        LICENSES.put("CDDL 1.0", "licenses/CDDL/cddl-1.0.txt");
        LICENSES.put("Common Public License 1.0", "licenses/CPL/cpl-1.0.txt");
        LICENSES.put("Eclipse Public License 1.0", "licenses/EPL/epl-1.0.txt");
        LICENSES.put("GNU Affero GPL 3.0", "licenses/GNU/agpl-3.0.txt");
        LICENSES.put("GNU GPL 1.0", "licenses/GNU/gpl-1.0.txt");
        LICENSES.put("GNU GPL 2.0", "licenses/GNU/gpl-2.0.txt");
        LICENSES.put("GNU GPL 3.0", "licenses/GNU/gpl-3.0.txt");
        LICENSES.put("GNU Lesser GPL 2.1", "licenses/GNU/lgpl-2.1.txt");
        LICENSES.put("GNU Lesser GPL 3.0", "licenses/GNU/lgpl-3.0.txt");
        LICENSES.put("MIT License", "licenses/MIT/license.txt");
        LICENSES.put("Mozilla Public License 1.0", "licenses/MPL/mpl-1.0.txt");
        LICENSES.put("Mozilla Public License 1.1", "licenses/MPL/mpl-1.1.txt");
        LICENSES.put("Mozilla Public License 2.0", "licenses/MPL/mpl-2.0.txt");
        LICENSES.put("Netscape Public License 1.0", "licenses/NPL/npl-1.0.txt");
        LICENSES.put("Netscape Public License 1.1", "licenses/NPL/npl-1.1.txt");
        LICENSES.put("PHP License 3.0", "licenses/PHP/php-3.0.txt");
        LICENSES.put("PHP License 3.01", "licenses/PHP/php-3.01.txt");
        LICENSES.put("Sun Public License 1.0", "licenses/SPL/spl-1.0.txt");
    }

    private static final LinkedHashMap<Integer, String> ROLE = new LinkedHashMap<Integer, String>();
    static
    {
        ROLE.put(1,"user");
        ROLE.put(2,"moderator");
        ROLE.put(3,"admin");

    }
    /**
     * The Hibernate SessionFactory
     */
    private SessionFactory sessionFactory;

    /**
     * Method is called when the application context is started or refreshed.
     * @param event A ContextRefreshedEvent
     */
    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        this.sessionFactory = (SessionFactory) event.getApplicationContext().getBean("sessionFactory");

        try {
            loadDefaultLicenses();
            loadDefaultRoles();
        } catch (IOException e) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn(e.getMessage());
            }
        }
    }

    /**
     * Loads the default licenses into the database if no license data exists.
     * @throws IOException An exception if the license file cannot be found
     */
    public void loadDefaultLicenses() throws IOException {
        final Session session = sessionFactory.openSession();
        final int count = ((Long) session.createQuery("select count(*) from License").uniqueResult()).intValue();

        // Check to see if data already exists in the table. If not, proceed to add default LICENSES.
        if (count > 0) {
            return;
        }

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Adding default licenses to datastore.");
        }
        for (Map.Entry<String, String> entry: LICENSES.entrySet()) {
            session.beginTransaction();

            final String licenseName = entry.getKey();
            final String licenseFile = entry.getValue();

            final String contentType = (licenseFile.endsWith(".html")) ? "text/html" : "text/plain";

            final License license = new License();
            license.setLicensename(licenseName);

            InputStream inputStream = null;
            Resource resource;
            try {
                resource = new ClassPathResource(licenseFile);
                license.setFilename(resource.getFilename());
                license.setContenttype(contentType);

                inputStream = resource.getInputStream();
                final Blob blob = Hibernate.createBlob(inputStream);
                license.setText(blob);
                session.save(license);
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("Added: " + licenseName);
                }
            } finally {
                IOUtils.closeQuietly(inputStream);
            }
            session.getTransaction().commit();
        }
        session.close();
    }

    /**
     * Loads the default Roles into the database if no Role data exists.
     */
    public void loadDefaultRoles()
    {


        final Session session = sessionFactory.openSession();
        session.beginTransaction();


        final int count = ((Long) session.createQuery("select count(*) from Roles ").uniqueResult()).intValue();


        // Check to see if data already exists in the table. If not, proceed to add default LICENSES.
        if (count > 0) {
            return;
        }

        for(String role:ROLE.values())
        {
            final Roles newrole = new Roles();
            newrole.setRole(role);
            session.save(newrole);
        }
        session.getTransaction().commit();
        session.close();
    }
}
