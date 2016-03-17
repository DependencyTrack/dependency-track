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

import org.hibernate.Query;
import org.hibernate.Session;
import org.owasp.dependencytrack.dao.BaseDao;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import java.util.List;


/**
 * Spring component that checks for incorrect or changes in data formats due to defects or upgrades
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Component
public class DataUpgradeCorrections extends BaseDao implements ApplicationListener<ContextRefreshedEvent> {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DataUpgradeCorrections.class);

    /**
     * Method is called when the application context is started or refreshed.
     *
     * @param event A ContextRefreshedEvent
     */
    public void onApplicationEvent(ContextRefreshedEvent event) {
        try {
            correctGeneratedSha1Length();
        } catch (Exception e) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn(e.getMessage());
            }
        } finally {
            cleanup(); // Closes all open sessions
        }
    }

    /**
     * MD5 and SHA1 hashes are dynamically computed by generating a UUID and stripping
     * the dashes. This works fine for MD5 which requires 32 characters, but fails for
     * SHA1 hashes which require 40 characters. This method identifies any 32 character
     * SHA1 hashes in the database and updates matching records with eight leading zeros.
     */
    @SuppressWarnings("unchecked")
	private void correctGeneratedSha1Length() {
        Session session = getSession();
        final Query query = session.createQuery("FROM LibraryVersion");
        final List<LibraryVersion> libraryVersions = query.list();
        session.getTransaction().begin();
        for (LibraryVersion libraryVersion: libraryVersions) {
            if (libraryVersion.getMd5() != null && libraryVersion.getSha1() != null && 32 == libraryVersion.getSha1().length()) {
                LOGGER.info("Identified incorrectly generated SHA1 hash: " + libraryVersion.getSha1());
                libraryVersion.setSha1("00000000" + libraryVersion.getMd5());
                session.save(libraryVersion);
                LOGGER.info("Corrected: " + libraryVersion.getSha1());
            }
        }
        session.getTransaction().commit();
    }

}
