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
import org.owasp.dependencytrack.event.LdapSyncEvent;
import org.owasp.dependencytrack.event.framework.EventService;
import org.owasp.dependencytrack.model.ApiKey;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Evidence;
import org.owasp.dependencytrack.model.LdapUser;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.Scan;
import org.owasp.dependencytrack.model.Team;
import org.owasp.dependencytrack.util.UuidUtil;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class QueryManager implements AutoCloseable {

    private static final boolean ENFORCE_AUTHORIZATION = Config.getInstance().getPropertyAsBoolean(Config.Key.ENFORCE_AUTHORIZATION);

    public enum OrderDirection {
        ASC, DESC
    }

    private PersistenceManager pm = LocalPersistenceManagerFactory.createPersistenceManager();

    @SuppressWarnings("unchecked")
    public ApiKey getApiKey(String key) {
        Query query = pm.newQuery(ApiKey.class, "key == :key");
        List<ApiKey> result = (List<ApiKey>)query.execute (key);
        return result.size() == 0 ? null : result.get(0);
    }

    public ApiKey regenerateApiKey(ApiKey apiKey) {
        pm.currentTransaction().begin();
        apiKey.setKey(UuidUtil.stripHyphens(UUID.randomUUID().toString()));
        pm.currentTransaction().commit();
        apiKey = pm.getObjectById(ApiKey.class, apiKey.getId());
        return apiKey;
    }

    public ApiKey createApiKey(Team team) {
        Set<Team> teams = new HashSet<>();
        teams.add(team);
        pm.currentTransaction().begin();
        ApiKey apiKey = new ApiKey();
        apiKey.setKey(UuidUtil.stripHyphens(UUID.randomUUID().toString()));
        apiKey.setTeams(teams);
        pm.makePersistent(apiKey);
        pm.currentTransaction().commit();
        return pm.getObjectById(ApiKey.class, apiKey.getId());
    }

    @SuppressWarnings("unchecked")
    public LdapUser getLdapUser(String username) {
        Query query = pm.newQuery(LdapUser.class, "username == :username");
        List<LdapUser> result = (List<LdapUser>)query.execute(username);
        return result.size() == 0 ? null : result.get(0);
    }

    @SuppressWarnings("unchecked")
    public List<LdapUser> getLdapUsers() {
        Query query = pm.newQuery(LdapUser.class);
        query.setOrdering("username " + OrderDirection.ASC.name());
        return (List<LdapUser>)query.execute();
    }

    public LdapUser createLdapUser(String username) {
        pm.currentTransaction().begin();
        LdapUser user = new LdapUser();
        user.setUsername(username);
        user.setDN("Syncing...");
        //todo - Implement lookup/sync service that automatically obtains and updates DN, or in the case of incorrect or deleted entries, mark DN as 'INVALID'
        pm.makePersistent(user);
        pm.currentTransaction().commit();
        EventService.getInstance().publish(new LdapSyncEvent(user.getUsername()));
        return getObjectById(LdapUser.class, user.getId());
    }

    public LdapUser updateUser(LdapUser transientUser) {
        LdapUser user = getObjectById(LdapUser.class, transientUser.getId());
        pm.currentTransaction().begin();
        user.setDN(transientUser.getDN());
        pm.currentTransaction().commit();
        return pm.getObjectById(LdapUser.class, user.getId());
    }

    public Team createTeam(String name, boolean createApiKey) {
        pm.currentTransaction().begin();
        Team team = new Team();
        team.setName(name);
        //todo assign permissions
        team.setUuid(UUID.randomUUID().toString());
        pm.makePersistent(team);
        pm.currentTransaction().commit();
        if (createApiKey) {
            createApiKey(team);
        }
        return getObjectByUuid(Team.class, team.getUuid(), Team.FetchGroup.ALL.getName());
    }

    @SuppressWarnings("unchecked")
    public List<Team> getTeams() {
        pm.getFetchPlan().addGroup(Team.FetchGroup.ALL.getName());
        Query query = pm.newQuery(Team.class);
        query.setOrdering("name " + OrderDirection.ASC.name());
        return (List<Team>)query.execute();
    }

    public Team updateTeam(Team transientTeam) {
        Team team = getObjectByUuid(Team.class, transientTeam.getUuid());
        pm.currentTransaction().begin();
        team.setName(transientTeam.getName());
        //todo assign permissions
        pm.currentTransaction().commit();
        return pm.getObjectById(Team.class, team.getId());
    }

    public boolean addUserToTeam(LdapUser user, Team team) {
        List<Team> teams = user.getTeams();
        boolean found = false;
        for (Team t: teams) {
            if (team.getUuid().equals(t.getUuid())) {
                found = true;
            }
        }
        if (!found) {
            pm.currentTransaction().begin();
            teams.add(team);
            user.setTeams(teams);
            pm.currentTransaction().commit();
            return true;
        }
        return false;
    }

    public boolean removeUserFromTeam(LdapUser user, Team team) {
        List<Team> teams = user.getTeams();
        boolean found = false;
        for (Team t: teams) {
            if (team.getUuid().equals(t.getUuid())) {
                found = true;
            }
        }
        if (found) {
            pm.currentTransaction().begin();
            teams.remove(team);
            user.setTeams(teams);
            pm.currentTransaction().commit();
            return true;
        }
        return false;
    }
    public Project createProject(String name) {
        Project project = new Project();
        project.setName(name);
        project.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(project);
        pm.currentTransaction().commit();
        return pm.getObjectById(Project.class, project.getId());
    }

    public Scan createScan(Project project, Date executed, Date imported) {
        Scan scan = new Scan();
        scan.setExecuted(executed);
        scan.setImported(imported);
        scan.setProject(project);
        scan.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(scan);
        pm.currentTransaction().commit();
        return pm.getObjectById(Scan.class, scan.getId());
    }

    public Component createComponent(String name, String filename, String md5, String sha1,
                                     String description, String license, Component parent) {
        Component component = new Component();
        component.setName(name);
        component.setFilename(filename);
        component.setMd5(md5);
        component.setSha1(sha1);
        component.setDescription(description);
        component.setLicense(license);
        component.setParent(parent);
        component.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(component);
        pm.currentTransaction().commit();
        return pm.getObjectById(Component.class, component.getId());
    }

    public Evidence createEvidence(Component component, String type, int confidenceScore,
                                    String source, String name, String value) {
        Evidence evidence = new Evidence();
        evidence.setComponent(component);
        evidence.setType(type);
        evidence.setConfidence(confidenceScore);
        evidence.setSource(source);
        evidence.setName(name);
        evidence.setValue(value);
        evidence.setUuid(UUID.randomUUID().toString());
        pm.currentTransaction().begin();
        pm.makePersistent(evidence);
        pm.currentTransaction().commit();
        return pm.getObjectById(Evidence.class, evidence.getId());
    }

    public void bind(Scan scan, Component component) {
        pm.currentTransaction().begin();
        scan.getComponents().add(component);
        component.getScans().add(scan);
        pm.currentTransaction().commit();
    }

    public void delete(Object... objects) {
        pm.currentTransaction().begin();
        pm.deletePersistentAll(objects);
        pm.currentTransaction().commit();
    }

    public void delete(Collection collection) {
        pm.currentTransaction().begin();
        pm.deletePersistentAll(collection);
        pm.currentTransaction().commit();
    }

    public <T>T getObjectById (Class<T> clazz, Object key) {
        return pm.getObjectById(clazz, key);
    }

    @SuppressWarnings("unchecked")
    public <T>T getObjectByUuid(Class<T> clazz, String uuid) {
        Query query = pm.newQuery(clazz, "uuid == :uuid");
        List<T> result = (List<T>)query.execute(uuid);
        return result.size() == 0 ? null : result.get(0);
    }

    @SuppressWarnings("unchecked")
    public <T>T getObjectByUuid(Class<T> clazz, String uuid, String fetchGroup) {
        pm.getFetchPlan().addGroup(fetchGroup);
        return getObjectByUuid(clazz, uuid);
    }

    public void close() {
        pm.close();
    }

    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }
}
