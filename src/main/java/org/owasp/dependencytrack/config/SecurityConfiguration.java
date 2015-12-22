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
package org.owasp.dependencytrack.config;

import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.WildcardPermissionResolver;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.authc.AnonymousFilter;
import org.apache.shiro.web.filter.authc.UserFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.owasp.dependencytrack.auth.BcryptCredentialsMatcher;
import org.owasp.dependencytrack.auth.JdbcConfigurableDefaultRoleRealm;
import org.owasp.dependencytrack.controller.token.TokenRequestDataValueProcessor;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import javax.servlet.Filter;
import javax.sql.DataSource;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by jason on 22/11/15.
 */
@Configuration
public class SecurityConfiguration {



    @Bean
    LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    public EhCacheManager cacheManager(){
        EhCacheManager ehCacheManager = new EhCacheManager();
        ehCacheManager.setCacheManager(new EhCacheManagerFactoryBean().getObject());
        return ehCacheManager;
    }

    @Bean(name="shiroFilter")
    ShiroFilterFactoryBean shiroFilterFactoryBean(DataSource dataSource){
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager(dataSource));
        shiroFilterFactoryBean.setLoginUrl("/login");
        shiroFilterFactoryBean.setSuccessUrl("/dashboard");
        // Linked hash map iterates entries in insertion order
        Map<String, String> pathMap = new LinkedHashMap<>();
        pathMap.put("/dcdata", "anon");
        pathMap.put("/libraryHierarchy", "anon");
        pathMap.put("/nist/**", "anon");
        pathMap.put("/beans/**", "anon");
        pathMap.put("/info/**", "anon");
        pathMap.put("/resources/**", "anon");
        pathMap.put("/registerUser", "anon");
        pathMap.put("/login", "anon");
        pathMap.put("/logout", "user");
        pathMap.put("/applications", "user");
        pathMap.put("/applicationVersion", "user");
        pathMap.put("/libraries", "user");
        pathMap.put("/vulnerabilities", "user");
        pathMap.put("/searchApplication", "user");
        pathMap.put("/dashboard", "user");
        pathMap.put("/error", "user");
        pathMap.put("/about", "user");
        pathMap.put("/**","user");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(pathMap);

        Map<String, Filter> filters = new HashMap<>();
        filters.put("anon", new AnonymousFilter());
        filters.put("user", new UserFilter());
        shiroFilterFactoryBean.setFilters(filters);
        return shiroFilterFactoryBean;
    }


    @Bean
    DefaultWebSecurityManager securityManager(DataSource dataSource) {
        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        Realm realm = jdbcRealm(dataSource);
        defaultWebSecurityManager.setRealm(realm);
        defaultWebSecurityManager.setCacheManager(cacheManager());
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        authenticator.setRealms(Arrays.asList(realm));
        authenticator.setAuthenticationStrategy(firstSuccessfulStrategy());
        defaultWebSecurityManager.setAuthenticator(authenticator);
        defaultWebSecurityManager.setAuthorizer(authorizer(dataSource,realm));
        return defaultWebSecurityManager;
    }

    @Bean
    public Authorizer authorizer(DataSource datasource,Realm realm) {
        ModularRealmAuthorizer modularRealmAuthorizer = new ModularRealmAuthorizer(Arrays.asList(realm));
        modularRealmAuthorizer.setPermissionResolver(permissionResolver());
        return modularRealmAuthorizer;
    }

    @Bean
    public WildcardPermissionResolver permissionResolver() {
        return new WildcardPermissionResolver();
    }

    @Bean
    public FirstSuccessfulStrategy firstSuccessfulStrategy() {
        return new FirstSuccessfulStrategy();
    }

    @Bean
    @DependsOn(value = "lifecycleBeanPostProcessor")
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        return defaultAdvisorAutoProxyCreator;
    }

    @Bean
    public BcryptCredentialsMatcher bcryptCredentialsMatcher() {
        return new BcryptCredentialsMatcher();
    }

    public static final String PERMISSIONS_QUERY = "SELECT p.permissionname FROM roles r, permissions p, roles_permissions rp"
            + " WHERE r.id=rp.roles_id AND"
            + " p.id=rp.permissions_id AND"
            + " r.role=?";
    public static final String USER_ROLES_QUERY = "SELECT role FROM roles r, users u WHERE u.username=? and r.ID=u.roleid";
    public static final String AUTHENTICATION_QUERY = "select password from users where username = ? and isldap = false";

    @Bean(name = "realm")
    @DependsOn("lifecycleBeanPostProcessor")
    public Realm jdbcRealm( DataSource dataSource) {
        JdbcConfigurableDefaultRoleRealm jdbcConfigurableDefaultRoleRealm = new JdbcConfigurableDefaultRoleRealm();
        jdbcConfigurableDefaultRoleRealm.setCredentialsMatcher(bcryptCredentialsMatcher());
        jdbcConfigurableDefaultRoleRealm.setDataSource(dataSource);
        jdbcConfigurableDefaultRoleRealm.setSaltStyle(JdbcRealm.SaltStyle.NO_SALT);
        jdbcConfigurableDefaultRoleRealm.setAuthenticationQuery(AUTHENTICATION_QUERY);
        jdbcConfigurableDefaultRoleRealm.setUserRolesQuery(USER_ROLES_QUERY);
        jdbcConfigurableDefaultRoleRealm.setPermissionsQuery(PERMISSIONS_QUERY);
        jdbcConfigurableDefaultRoleRealm.setPermissionsLookupEnabled(true);
        jdbcConfigurableDefaultRoleRealm.init();
        return jdbcConfigurableDefaultRoleRealm;
    }

    //CSRF Prevention
    @Bean(name = "requestDataValueProcessor")
    public TokenRequestDataValueProcessor tokenRequestDataValueProcessor(){
        TokenRequestDataValueProcessor tokenRequestDataValueProcessor = new TokenRequestDataValueProcessor();
        return tokenRequestDataValueProcessor;
    }

}
