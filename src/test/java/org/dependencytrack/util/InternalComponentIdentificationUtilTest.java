package org.dependencytrack.util;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class InternalComponentIdentificationUtilTest extends PersistenceCapableTest {

    private final String groupsRegexProperty;
    private final String componentGroup;
    private final String namesRegexProperty;
    private final String componentName;
    private final boolean shouldBeInternal;

    @Parameterized.Parameters(name = "[{index}] groupsRegexProperty={0} componentGroup={1} " +
            "namesRegexProperty={2} componentName={3} shouldBeInternal={4}")
    public static Collection testParameters() {
        return Arrays.asList(new Object[][]{
                // neither regexes nor group / name provided
                {"", "", "", "", false},
                // Neither group nor name provided
                {".*", null, ".*", null, false},
                // group matches, name not provided
                {".*", "a", ".*", null, true},
                // group not provided, name matches
                {".*", null, ".*", "a", true},
                // both group and name match
                {".*", "a", ".*", "b", true},
                // specific regex for group
                {"^us\\.springett$", "us.springett", null, null, true},
                // specific regex for name
                {null, null, "^dependency-track$", "dependency-track", true},
                // generalized, case-insensitive regex for group
                {"(?i)^(org\\.apache)(\\.[\\w.]+)?$", "Org.Apache.Logging.Log4J", null, "log4j-test", true},
                // same as above, but with incomplete regex
                {"(?i)^(org\\.apache)", "Org.Apache.Logging.Log4J", null, "log4j-test", false},
                // generalized regex for names
                {null, "org.apache.logging.log4j", "^(log4j-)([\\w-]+)$", "log4j-test", true},
                // same as above, but with incomplete regex
                {null, "org.apache.logging.log4j", "^(log4j-)", "log4j-test", false},
        });
    }

    public InternalComponentIdentificationUtilTest(final String groupsRegexProperty, final String componentGroup,
                                                   final String namesRegexProperty, final String componentName,
                                                   final boolean shouldBeInternal) {
        this.groupsRegexProperty = groupsRegexProperty;
        this.componentGroup = componentGroup;
        this.namesRegexProperty = namesRegexProperty;
        this.componentName = componentName;
        this.shouldBeInternal = shouldBeInternal;
    }

    @Test
    public void testIsInternal() {
        qm.createConfigProperty(
                INTERNAL_COMPONENTS_GROUPS_REGEX.getGroupName(),
                INTERNAL_COMPONENTS_GROUPS_REGEX.getPropertyName(),
                groupsRegexProperty,
                INTERNAL_COMPONENTS_GROUPS_REGEX.getPropertyType(),
                INTERNAL_COMPONENTS_GROUPS_REGEX.getDescription()
        );
        qm.createConfigProperty(
                INTERNAL_COMPONENTS_NAMES_REGEX.getGroupName(),
                INTERNAL_COMPONENTS_NAMES_REGEX.getPropertyName(),
                namesRegexProperty,
                INTERNAL_COMPONENTS_NAMES_REGEX.getPropertyType(),
                INTERNAL_COMPONENTS_NAMES_REGEX.getDescription()
        );

        final Component component = new Component();
        component.setGroup(componentGroup);
        component.setName(componentName);

        assertEquals(shouldBeInternal, InternalComponentIdentificationUtil.isInternalComponent(component));
    }

}
