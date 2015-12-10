package org.owasp.dependencytrack.model;

import org.springframework.boot.orm.jpa.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Created by jason on 23/11/15.
 */
@Configuration
@ComponentScan
@EntityScan
public class AllEntities {
}
