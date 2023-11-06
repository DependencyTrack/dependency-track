package org.dependencytrack.util;

import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

public class VersionDistanceTest {

    @Test
    public void testVersionDistance() {
        Assert.assertEquals("0:1.?.?", new VersionDistance("1").toString());
        Assert.assertEquals("1:?.?.?", new VersionDistance("1:?").toString());
        Assert.assertEquals("0:0.0.0", new VersionDistance().toString());
        Assert.assertEquals("0:0.0.0", new VersionDistance(null).toString());
        Assert.assertEquals("0:0.0.0", new VersionDistance(0,0,0).toString());
        Assert.assertEquals("0:1.?.?", new VersionDistance(1, -1,-1).toString());
        Assert.assertEquals("0:0.2.?", new VersionDistance(0, 2, -1).toString());
        Assert.assertEquals("0:0.2.?", new VersionDistance("0:0.2").toString());
        Assert.assertEquals("0:2.?.?", new VersionDistance("2").toString());

        Assert.assertThrows(NumberFormatException.class, () -> new VersionDistance("ax").toString());
        Assert.assertThrows(NumberFormatException.class, () -> new VersionDistance("1a").toString());
        Assert.assertThrows(NumberFormatException.class, () -> new VersionDistance("1.2.3.4").toString());
        Assert.assertThrows(NumberFormatException.class, () -> new VersionDistance("1a.2b.3c").toString());
        Assert.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("1.0.0").toString());
        Assert.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("1.1.0").toString());
        Assert.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("?:1.0.0").toString());
        Assert.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("0:?.0.0").toString());
        Assert.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("?:1.0.0").toString());
        Assert.assertThrows(IllegalArgumentException.class, () -> new VersionDistance("0:?.1.0").toString());
    }

    @Test
    public void testCompareTo() {
        Assert.assertEquals(0, new VersionDistance(null).compareTo(new VersionDistance("0")));
        Assert.assertTrue(new VersionDistance("2.?.?").compareTo(new VersionDistance("1.?.?")) > 0);

        Assert.assertEquals(0, new VersionDistance().compareTo(new VersionDistance()));
        Assert.assertEquals(0, new VersionDistance("0.0").compareTo(new VersionDistance("0")));
        Assert.assertEquals(0, new VersionDistance("1.?.?").compareTo(new VersionDistance("1.?.?")));

        Assert.assertTrue(new VersionDistance("1").compareTo(new VersionDistance()) > 0);
        Assert.assertTrue(new VersionDistance("1").compareTo(new VersionDistance(null)) > 0);
        Assert.assertTrue(new VersionDistance("1.?").compareTo(new VersionDistance("0")) > 0);
        Assert.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("0.0")) > 0);
        Assert.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("0.0.0")) > 0);
        Assert.assertTrue(new VersionDistance("2.?.?").compareTo(new VersionDistance("1.?.?")) > 0);
        Assert.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("0.1.?")) > 0);
        Assert.assertTrue(new VersionDistance("0.1.?").compareTo(new VersionDistance("0.0.1")) > 0);

        Assert.assertTrue(new VersionDistance().compareTo(new VersionDistance("1")) < 0);
        Assert.assertTrue(new VersionDistance(null).compareTo(new VersionDistance("1")) < 0);
        Assert.assertTrue(new VersionDistance("0").compareTo(new VersionDistance("1.?")) < 0);
        Assert.assertTrue(new VersionDistance("0.0").compareTo(new VersionDistance("0.0.1")) < 0);
        Assert.assertTrue(new VersionDistance("0.1.?").compareTo(new VersionDistance("1.?.?")) < 0);
        Assert.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("2.?.?")) < 0);
        Assert.assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("2.?.?")) < 0);
        Assert.assertTrue(new VersionDistance("0.1.?").compareTo(new VersionDistance("0.2.?")) < 0);
        Assert.assertTrue(new VersionDistance("0.0.1").compareTo(new VersionDistance("0.0.2")) < 0);

        Assert.assertTrue(VersionDistance.getVersionDistance("1.0.0", "0.1.0").compareTo(new VersionDistance("1.?.?")) == 0);
        Assert.assertTrue(VersionDistance.getVersionDistance("1.1.0", "1.0.0").compareTo(new VersionDistance("0.1.?")) == 0);
        Assert.assertTrue(VersionDistance.getVersionDistance("1.0.0", "1.1.0").compareTo(new VersionDistance("0.1.?")) == 0);
        Assert.assertTrue(VersionDistance.getVersionDistance("1.2.3", "2.1.0").compareTo(new VersionDistance("1.?.?")) == 0);
        Assert.assertTrue(VersionDistance.getVersionDistance("2.2.2", "2.4.4").compareTo(new VersionDistance("0.1.?")) > 0);
        Assert.assertTrue(VersionDistance.getVersionDistance("1.1.1", "1.1.3").compareTo(new VersionDistance("0.0.1")) > 0);
    }

    @Test
    public void testEquals() {
        Assert.assertEquals(new VersionDistance("0.0"), new VersionDistance(""));
        Assert.assertEquals(new VersionDistance("0:0"), new VersionDistance(null));
        Assert.assertEquals(new VersionDistance("4:?.?.?"), new VersionDistance("4:?"));
        Assert.assertEquals(new VersionDistance("1.?.?"), new VersionDistance("1"));
        Assert.assertEquals(new VersionDistance("0:1.?.?"), new VersionDistance("1.?"));
    }

    @Test
    public void testGetVersionDistance() {
        Assert.assertEquals(new VersionDistance("0.0.0"), VersionDistance.getVersionDistance("", null));
        Assert.assertEquals(new VersionDistance("0.0.0"), VersionDistance.getVersionDistance(null, ""));
        Assert.assertEquals(new VersionDistance("1.?.?"), VersionDistance.getVersionDistance("2", "1.0"));
        Assert.assertEquals(new VersionDistance("0.1.?"), VersionDistance.getVersionDistance("1", "1.1.0"));
        Assert.assertEquals(new VersionDistance("0.0.1"), VersionDistance.getVersionDistance("1", "1.0.1"));
        Assert.assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("1.2", "3.4.0"));
        Assert.assertEquals(new VersionDistance("0:2.?"), VersionDistance.getVersionDistance("1.f", "3.4.0"));
        Assert.assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("1.", "3.4.0"));
        Assert.assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("1.2.3", "3.4.0"));
        Assert.assertEquals(new VersionDistance("3.?.?"), VersionDistance.getVersionDistance("0.1.2", "3.4.0"));
        Assert.assertEquals(new VersionDistance("0.2.?"), VersionDistance.getVersionDistance("3.2.2", "3.4.0"));
        Assert.assertEquals(new VersionDistance("0.0.1"), VersionDistance.getVersionDistance("0.0.1", "0.0.2"));
        Assert.assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("3.4.0", "1.2.3"));
        Assert.assertEquals(new VersionDistance("3.?.?"), VersionDistance.getVersionDistance("3.4.0", "0.1.2"));
        Assert.assertEquals(new VersionDistance("0.2.?"), VersionDistance.getVersionDistance("3.4.0", "3.2.2"));
        Assert.assertEquals(new VersionDistance("0.0.1"), VersionDistance.getVersionDistance("0.0.2", "0.0.1"));
        // optional build numbers are ignored:
        Assert.assertEquals(new VersionDistance("0.0.0"), VersionDistance.getVersionDistance("0.0.0.1", "0.0.0.5"));

        Assert.assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("a:", "1"));
        Assert.assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("1a.2.3", "1"));
        Assert.assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("1.2a.3", "1"));
        Assert.assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("1.2.3a", "1"));
    }

    @Test
    public void testParse() {
        Assert.assertEquals(Arrays.asList(new VersionDistance(0,1,-1)), VersionDistance.parse("0.1.?"));
        Assert.assertEquals(Arrays.asList(new VersionDistance(1,-1,-1), new VersionDistance(0,1,-1)), VersionDistance.parse("1.1.?"));
        Assert.assertEquals(Arrays.asList(new VersionDistance(1, -1,-1,-1), new VersionDistance(1,-1, -1), new VersionDistance(0,1,-1)), VersionDistance.parse("1:1.1.?"));
        Assert.assertEquals(Arrays.asList(), VersionDistance.parse("0:?.?.?"));

        Assert.assertThrows(IllegalArgumentException.class, () -> VersionDistance.parse("1.2.3a.1"));
    }

}