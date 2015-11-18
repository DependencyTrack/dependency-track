package config;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.internal.matchers.StringContains.containsString;

/**
 * Created by jason on 18/11/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:spring/properties.xml")
public class PropertiesTest {

    @Value("${app.data.dir}")
    private String appDataDir;

    @Test
    public void shouldAutowirePropertiesCorrectly(){
        assertThat(appDataDir,not(nullValue()));
        assertThat(appDataDir,not(containsString("app.data.dir")));
        assertThat(appDataDir,not(containsString("user.home")));
        System.out.println("appDataDir = " + appDataDir);
    }

}
