package org.owasp.dependencytrack.config;

import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

/**
 * Created by jason on 18/11/15.
 */
@Configuration
public class PropertyConfiguration {

    @Bean
    PropertyPlaceholderConfigurer propertyPlaceholderConfigurer(){
        PropertyPlaceholderConfigurer propertyPlaceholderConfigurer = new PropertyPlaceholderConfigurer();
        propertyPlaceholderConfigurer.setSearchSystemEnvironment(true);
        propertyPlaceholderConfigurer.setLocations(new ClassPathResource("application.properties"));
        return propertyPlaceholderConfigurer;
    }
}
