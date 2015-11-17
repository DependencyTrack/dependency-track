package org.owasp.dependencytrack.config;

import org.hibernate.SessionFactory;
import org.owasp.dependencytrack.tasks.NistDataMirrorUpdater;
import org.owasp.dependencytrack.tasks.VulnerabilityScanTask;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.ApplicationEventMulticaster;
import org.springframework.context.event.SimpleApplicationEventMulticaster;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.orm.hibernate4.HibernateTransactionManager;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Created by jason on 16/11/15.
 */
@Configuration
@Import({DatabaseConfguration.class})
@EnableAspectJAutoProxy
@EnableAsync
public class ApplicationConfiguration {

    //    <!-- Dependency-Check scan agent scheduler -->
    @Bean
    public VulnerabilityScanTask vulnerabilityScanTask(SessionFactory sessionFactory){
        return new VulnerabilityScanTask();
    }

    @Bean
    public NistDataMirrorUpdater nistDataMirrorUpdater() {
        return new NistDataMirrorUpdater();
    }

    @Bean(name = "properties")
    public PropertiesFactoryBean properties() {
        PropertiesFactoryBean bean = new PropertiesFactoryBean();
        bean.setLocation(new ClassPathResource("application.properties"));
        return bean;
    }

    @Bean
    public HibernateTransactionManager hibernateTransactionManager(SessionFactory sessionFactory){
        return new HibernateTransactionManager( sessionFactory );
    }

    @Bean
    public ApplicationEventMulticaster applicationEventMulticaster() {
        SimpleApplicationEventMulticaster simpleApplicationEventMulticaster = new SimpleApplicationEventMulticaster();
        simpleApplicationEventMulticaster.setTaskExecutor(new SimpleAsyncTaskExecutor());
        return simpleApplicationEventMulticaster;
    }
}
