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
package org.owasp.dependencytrack.persistence;

import org.owasp.dependencytrack.Config;
import org.owasp.dependencytrack.ConfigItem;
import org.owasp.dependencytrack.model.ApiKey;
import org.owasp.dependencytrack.model.LdapUser;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.List;

public class QueryManager {

    private static final boolean ENFORCE_AUTHORIZATION = Config.getInstance().getPropertyAsBoolean(ConfigItem.ENFORCE_AUTHORIZATION);

    public enum OrderDirection {
        ASC, DESC
    }

    private PersistenceManager getPersistenceManager() {
        return LocalPersistenceManagerFactory.createPersistenceManager();
    }

    @SuppressWarnings("unchecked")
    public ApiKey getApiKey(String key) {
        PersistenceManager pm = getPersistenceManager();
        Query query = pm.newQuery(ApiKey.class, "key == :key");
        List<ApiKey> result = (List<ApiKey>)query.execute (key);
        pm.close();
        return result.size() == 0 ? null : result.get(0);
    }

    @SuppressWarnings("unchecked")
    public LdapUser getLdapUser(String username) {
        PersistenceManager pm = getPersistenceManager();
        Query query = pm.newQuery(LdapUser.class, "username == :username");
        List<LdapUser> result = (List<LdapUser>)query.execute(username);
        pm.close();
        return result.size() == 0 ? null : result.get(0);
    }

    @SuppressWarnings("unchecked")
    public List<LdapUser> getLdapUsers() {
        PersistenceManager pm = getPersistenceManager();
        Query query = pm.newQuery(LdapUser.class);
        query.setOrdering("username " + OrderDirection.ASC.name());
        List<LdapUser> result = (List<LdapUser>)query.execute();
        pm.close();
        return result;
    }

}
