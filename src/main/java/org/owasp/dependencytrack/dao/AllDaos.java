package org.owasp.dependencytrack.dao;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Created by jason on 16/11/15.
 */
@Configuration
@ComponentScan
public class AllDaos {

    @Bean
    public String test(){
        return "Hello";
    }
}
