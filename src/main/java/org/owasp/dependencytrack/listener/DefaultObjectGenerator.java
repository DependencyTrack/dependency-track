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
package org.owasp.dependencytrack.listener;

import org.apache.commons.io.IOUtils;
import org.hibernate.Hibernate;
import org.hibernate.Query;
import org.hibernate.Session;
import org.owasp.dependencytrack.dao.BaseDao;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Permissions;
import org.owasp.dependencytrack.model.Roles;
import org.owasp.dependencytrack.model.User;
import org.owasp.dependencytrack.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Blob;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;


/**
 * Spring component that initializes all data objects necessary for a new install.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Component
public class DefaultObjectGenerator extends BaseDao implements ApplicationListener<ContextRefreshedEvent> {

    static CountDownLatch initialised = new CountDownLatch(1);

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultObjectGenerator.class);

    /**
     * Specify default license names and files
     */
    private static final LinkedHashMap<String, String> LICENSES;

    @Autowired
    UserService userService;

    private Session session;

    static {
        LICENSES = new LinkedHashMap<>();
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

    /**
     * Specify default Permission names
     */
    private static final LinkedHashMap<String, Roles.ROLE> PERMISSIONS = new LinkedHashMap<>();

    static {
        PERMISSIONS.put("applications", Roles.ROLE.USER);
        PERMISSIONS.put("searchApplication", Roles.ROLE.USER);
        PERMISSIONS.put("coarseSearchApplication", Roles.ROLE.USER);
        PERMISSIONS.put("keywordSearchLibraries", Roles.ROLE.USER);
        PERMISSIONS.put("libraryHierarchy", Roles.ROLE.USER);
        PERMISSIONS.put("applicationVersion", Roles.ROLE.USER);
        PERMISSIONS.put("vulnerabilities", Roles.ROLE.USER);
        PERMISSIONS.put("libraries", Roles.ROLE.USER);
        PERMISSIONS.put("downloadlicense", Roles.ROLE.USER);
        PERMISSIONS.put("viewlicense", Roles.ROLE.USER);
        PERMISSIONS.put("dcdata", Roles.ROLE.USER);
        PERMISSIONS.put("about", Roles.ROLE.USER);
        PERMISSIONS.put("dashboard", Roles.ROLE.USER);
        PERMISSIONS.put("addApplication", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("updateApplication", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("updateApplicationVersion", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("deleteApplication", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("deleteApplicationVersion", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("addApplicationVersion", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("addDependency", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("deleteDependency", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("cloneApplication", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("cloneApplicationVersion", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("updatelibrary", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("removelibrary", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("addlibraries", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("uploadlicense", Roles.ROLE.MODERATOR);
        PERMISSIONS.put("usermanagement", Roles.ROLE.ADMIN);
        PERMISSIONS.put("validateuser", Roles.ROLE.ADMIN);
        PERMISSIONS.put("deleteuser", Roles.ROLE.ADMIN);
        PERMISSIONS.put("changeuserrole", Roles.ROLE.ADMIN);
    }

    public DefaultObjectGenerator() {

    }

    /**
     * Method is called when the application context is started or refreshed. @param event A ContextRefreshedEvent
     */
    public void onApplicationEvent(ContextRefreshedEvent event) {
        this.session = super.getSession();
        try {
            loadDefaultLicenses();
            loadDefaultPermissions();
            loadDefaultRoles();
            loadDefaultUsers();
        } catch (IOException e) {
            if (LOGGER.isWarnEnabled()) LOGGER.warn(e.getMessage());
        }
        finally {
            initialised.countDown();
        }
    }

    /**
     * Loads the default licenses into the database if no license data exists. @throws IOException An exception if the license file cannot be found
     */
    private void loadDefaultLicenses() throws IOException {
        if (getCount(session, License.class) > 0) {
            return;
        }
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Adding default licenses to datastore.");
        }
        session.beginTransaction();
        for (Map.Entry<String, String> entry : LICENSES.entrySet()) {
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

                String licenceFileContent = new String(IOUtils.toCharArray(inputStream));
                final Blob blob = Hibernate.getLobCreator(session).createBlob(licenceFileContent.getBytes());

                license.setText(blob);
                session.save(license);
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("Added: " + licenseName);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                IOUtils.closeQuietly(inputStream);
            }
        }
        session.getTransaction().commit();
    }

    /**
     * Loads the default permissions into the database if no permission data exists.
     */
    private void loadDefaultPermissions() {
        if (getCount(session, Permissions.class) > 0) {
            return;
        }
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Adding default permissions to datastore.");
        }
        session.beginTransaction();
        for (Map.Entry<String, Roles.ROLE> entry : PERMISSIONS.entrySet()) {
            final Permissions permission = new Permissions(entry.getKey());
            session.save(permission);
        }
        session.getTransaction().commit();
    }

    /**
     * Loads the default Roles into the database if no Role data exists.
     */
    @SuppressWarnings("unchecked")
    private void loadDefaultRoles() {
        if (getCount(session, Roles.class) > 0) {
            return;
        }
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Adding default roles to datastore.");
        }
        // Retrieve a list of all persisted permissions
        final Query query = session.createQuery("FROM Permissions");
        final List<Permissions> permissions = query.list();

        Map<Roles.ROLE,Roles> rolesMap = new HashMap<>();

        for (Roles.ROLE eachRole : Roles.ROLE.values()) {
            Roles role = new Roles(eachRole.name().toLowerCase());
            rolesMap.put(eachRole,role);
        }

        Roles userRole = rolesMap.get(Roles.ROLE.USER);
        Roles moderatorRole = rolesMap.get(Roles.ROLE.MODERATOR);
        Roles adminRole = rolesMap.get(Roles.ROLE.ADMIN);

        session.beginTransaction();
        for (Permissions permission : permissions) {
            adminRole.addPermission(permission);
            if (getRole(permission) == Roles.ROLE.USER) {
                userRole.addPermission(permission);
                moderatorRole.addPermission(permission);
            }
            if (getRole(permission) == Roles.ROLE.MODERATOR) {
                moderatorRole.addPermission(permission);
            }
        }
        for (Roles eachRole : rolesMap.values()) {
            session.save(eachRole);
        }
        session.getTransaction().commit();
    }

    private Roles.ROLE getRole(Permissions permission) {
        return PERMISSIONS.get(permission.getPermissionname());
    }

    /**
     * Loads the default users into the database if no User data exists.
     */
    @SuppressWarnings("unchecked")
    private void loadDefaultUsers() {
        if (getCount(session, User.class) > 0) {
            return;
        }
        userService.registerUser("admin", false, "admin", Roles.ROLE.ADMIN);
    }

}
