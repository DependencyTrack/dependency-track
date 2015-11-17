package org.owasp.dependencytrack.config;

import org.apache.commons.dbcp.BasicDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.orm.hibernate4.LocalSessionFactoryBean;

import javax.sql.DataSource;
import java.util.Properties;

/**
 * Created by jason on 16/11/15.
 */
public class DatabaseConfguration
{
    @Bean
    public DataSource dataSource(){
        BasicDataSource basicDataSource = new BasicDataSource();
        basicDataSource.setDriverClassName("org.h2.Driver");
        basicDataSource.setUsername("sa");
        basicDataSource.setPassword("");
        basicDataSource.setUrl("jdbc:h2:~/dependency-track/database;MVCC=TRUE;AUTO_SERVER=TRUE");
        return basicDataSource;
    }

    @Bean
    public LocalSessionFactoryBean sessionFactory(){
        LocalSessionFactoryBean localSessionFactoryBean = new LocalSessionFactoryBean();
        localSessionFactoryBean.setDataSource(dataSource());
        localSessionFactoryBean.setConfigLocation(new ClassPathResource("hibernate.cfg.xml"));
        localSessionFactoryBean.setHibernateProperties(hibernateProperties());
        return localSessionFactoryBean;
    }

    @Bean
    public Properties hibernateProperties(){
        Properties properties = new Properties();
        properties.setProperty("hibernate.dialect","org.hibernate.dialect.H2Dialect");
        properties.setProperty("hibernate.show_sql","false");
        properties.setProperty("hibernate.hbm2ddl.auto","update");
        return properties;
    }


}
