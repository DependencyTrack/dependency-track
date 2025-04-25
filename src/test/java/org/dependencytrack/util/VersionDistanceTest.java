package org.dependencytrack.util;

import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class VersionDistanceTest {

    @Test
    void testVersionDistance() {
        Assertions.assertEquals("0:1.?.?", new VersionDistance("1").toString());
        Assertions.assertEquals("1:?.?.?", new VersionDistance("1:?").toString());
        Assertions.assertEquals("0:0.0.0", new VersionDistance().toString());
        Assertions.assertEquals("0:0.0.0", new VersionDistance(null).toString());
        Assertions.assertEquals("0:0.0.0", new VersionDistance(0,0,0).toString());
        Assertions.assertEquals("0:1.?.?", new VersionDistance(1, -1,-1).toString());
        Assertions.assertEquals("0:0.2.?", new VersionDistance(0, 2, -1).toString());
        Assertions.assertEquals("0:0.2.?", new VersionDistance("0:0.2").toString());
        Assertions.assertEquals("0:2.?.?", new VersionDistance("2").toString());

        Assertions.assertThrows(NumberFormatException.class, () -> new VersionDistance("ax").toString());
        Assertions.assertThrows(NumberFormatException.class, () -> new VersionDistance("1a").toString());
        Assertions.assertThrows(NumberFormatException.class, () -> new VersionDistance("1.2.3.4").toString());
        Assertions.assertThrows(NumberFormatException.class, () -> new VersionDistance("1a.2b.3c").toString());
        Assertions.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("1.0.0").toString());
        Assertions.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("1.1.0").toString());
        Assertions.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("?:1.0.0").toString());
        Assertions.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("0:?.0.0").toString());
        Assertions.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("?:1.0.0").toString());
        Assertions.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("0:?.1.0").toString());
    }

    @Test
    void testCompareTo() {
        Assertions.assertEquals(0, new VersionDistance(null).compareTo(new VersionDistance("0")));
        Assertions.assertTrue(new VersionDistance("2.?.?").compareTo(new VersionDistance("1.?.?")) > 0);

        Assertions.assertEquals(0, new VersionDistance().compareTo(new VersionDistance()));
        Assertions.assertEquals(0, new VersionDistance("0.0").compareTo(new VersionDistance("0")));
        Assertions.assertEquals(0, new VersionDistance("1.?.?").compareTo(new VersionDistance("1.?.?")));

        Assertions.assertTrue(new VersionDistance("1").compareTo(new VersionDistance()) > 0);
        Assertions.assertTrue(new VersionDistance("1").compareTo(new VersionDistance(null)) > 0);
        Assertions.assertTrue(new VersionDistance("1.?").compareTo(new VersionDistance("0")) > 0);
        Assertions.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("0.0")) > 0);
        Assertions.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("0.0.0")) > 0);
        Assertions.assertTrue(new VersionDistance("2.?.?").compareTo(new VersionDistance("1.?.?")) > 0);
        Assertions.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("0.1.?")) > 0);
        Assertions.assertTrue(new VersionDistance("0.1.?").compareTo(new VersionDistance("0.0.1")) > 0);

        Assertions.assertTrue(new VersionDistance().compareTo(new VersionDistance("1")) < 0);
        Assertions.assertTrue(new VersionDistance(null).compareTo(new VersionDistance("1")) < 0);
        Assertions.assertTrue(new VersionDistance("0").compareTo(new VersionDistance("1.?")) < 0);
        Assertions.assertTrue(new VersionDistance("0.0").compareTo(new VersionDistance("0.0.1")) < 0);
        Assertions.assertTrue(new VersionDistance("0.1.?").compareTo(new VersionDistance("1.?.?")) < 0);
        Assertions.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("2.?.?")) < 0);
        Assertions.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("2.?.?")) < 0);
        Assertions.assertTrue(new VersionDistance("0.1.?").compareTo(new VersionDistance("0.2.?")) < 0);
        Assertions.assertTrue(new VersionDistance("0.0.1").compareTo(new VersionDistance("0.0.2")) < 0);

        Assertions.assertTrue(VersionDistance.getVersionDistance("1.0.0", "0.1.0").compareTo(new VersionDistance("1.?.?")) == 0);
        Assertions.assertTrue(VersionDistance.getVersionDistance("1.1.0", "1.0.0").compareTo(new VersionDistance("0.1.?")) == 0);
        Assertions.assertTrue(VersionDistance.getVersionDistance("1.0.0", "1.1.0").compareTo(new VersionDistance("0.1.?")) == 0);
        Assertions.assertTrue(VersionDistance.getVersionDistance("1.2.3", "2.1.0").compareTo(new VersionDistance("1.?.?")) == 0);
        Assertions.assertTrue(VersionDistance.getVersionDistance("2.2.2", "2.4.4").compareTo(new VersionDistance("0.1.?")) > 0);
        Assertions.assertTrue(VersionDistance.getVersionDistance("1.1.1", "1.1.3").compareTo(new VersionDistance("0.0.1")) > 0);
    }

    @Test
    void testEquals() {
        Assertions.assertEquals(new VersionDistance("0.0"), new VersionDistance(""));
        Assertions.assertEquals(new VersionDistance("0:0"), new VersionDistance(null));
        Assertions.assertEquals(new VersionDistance("4:?.?.?"), new VersionDistance("4:?"));
        Assertions.assertEquals(new VersionDistance("1.?.?"), new VersionDistance("1"));
        Assertions.assertEquals(new VersionDistance("0:1.?.?"), new VersionDistance("1.?"));
    }

    @Test
    void testGetVersionDistance() {
        Assertions.assertEquals(new VersionDistance("0.0.0"), VersionDistance.getVersionDistance("", null));
        Assertions.assertEquals(new VersionDistance("0.0.0"), VersionDistance.getVersionDistance(null, ""));
        Assertions.assertEquals(new VersionDistance("1.?.?"), VersionDistance.getVersionDistance("2", "1.0"));
        Assertions.assertEquals(new VersionDistance("0.1.?"), VersionDistance.getVersionDistance("1", "1.1.0"));
        Assertions.assertEquals(new VersionDistance("0.0.1"), VersionDistance.getVersionDistance("1", "1.0.1"));
        Assertions.assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("1.2", "3.4.0"));
        Assertions.assertEquals(new VersionDistance("0:2.?"), VersionDistance.getVersionDistance("1.f", "3.4.0"));
        Assertions.assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("1.", "3.4.0"));
        Assertions.assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("1.2.3", "3.4.0"));
        Assertions.assertEquals(new VersionDistance("3.?.?"), VersionDistance.getVersionDistance("0.1.2", "3.4.0"));
        Assertions.assertEquals(new VersionDistance("0.2.?"), VersionDistance.getVersionDistance("3.2.2", "3.4.0"));
        Assertions.assertEquals(new VersionDistance("0.0.1"), VersionDistance.getVersionDistance("0.0.1", "0.0.2"));
        Assertions.assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("3.4.0", "1.2.3"));
        Assertions.assertEquals(new VersionDistance("3.?.?"), VersionDistance.getVersionDistance("3.4.0", "0.1.2"));
        Assertions.assertEquals(new VersionDistance("0.2.?"), VersionDistance.getVersionDistance("3.4.0", "3.2.2"));
        Assertions.assertEquals(new VersionDistance("0.0.1"), VersionDistance.getVersionDistance("0.0.2", "0.0.1"));
        // optional build numbers are ignored:
        Assertions.assertEquals(new VersionDistance("0.0.0"), VersionDistance.getVersionDistance("0.0.0.1", "0.0.0.5"));

        Assertions.assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("a:", "1"));
        Assertions.assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("1a.2.3", "1"));
        Assertions.assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("1.2a.3", "1"));
        Assertions.assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("1.2.3a", "1"));
    }

    @Test
    void testParse() {
        Assertions.assertEquals(Arrays.asList(new VersionDistance(0,1,-1)), VersionDistance.parse("0.1.?"));
        Assertions.assertEquals(Arrays.asList(new VersionDistance(1,-1,-1), new VersionDistance(0,1,-1)), VersionDistance.parse("1.1.?"));
        Assertions.assertEquals(Arrays.asList(new VersionDistance(1, -1,-1,-1), new VersionDistance(1,-1, -1), new VersionDistance(0,1,-1)), VersionDistance.parse("1:1.1.?"));
        Assertions.assertEquals(Arrays.asList(), VersionDistance.parse("0:?.?.?"));

        Assertions.assertThrows(IllegalArgumentException.class, () -> VersionDistance.parse("1.2.3a.1"));
    }

}