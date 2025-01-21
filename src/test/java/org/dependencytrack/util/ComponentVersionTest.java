package org.dependencytrack.util;

import com.github.packageurl.PackageURL;
import org.junit.Assert;
import org.junit.Test;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.ArrayList;
import java.io.IOException;
import java.util.Random;

public class ComponentVersionTest {
    @Test
    public void testParseVersion() {
        String versionString = "0:1.a.#b+c-d~e";
        Ecosystem ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);
        ComponentVersion version = new ComponentVersion(ecosystem, versionString);
        Assert.assertEquals(versionString, version.toString());
    }

    @Test
    public void testGeneric() {
        Ecosystem ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.GENERIC);

        List<String[]> list = new ArrayList<>();
        list.add(new String[]{"1.0.0","2.0.0"});
        list.add(new String[]{"4.17.1","6.15.1"});
        list.add(new String[]{"0.0.5","24.0.0"});
        list.add(new String[]{"3.0.11","3.2.5"});
        list.add(new String[]{"7.0.5","7.0.5"});

        // Iterate over the list and print each array
        for (String[] version : list) {
            ComponentVersion version1 = new ComponentVersion(ecosystem, version[0]);
            ComponentVersion version2 = new ComponentVersion(ecosystem, version[1]);

            Assert.assertTrue(version1.compareTo(version2) <= 0);
        }
    }

    @Test
    public void testSimpleOpensslVersion() {
        Ecosystem ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);
        ComponentVersion version_1_1_0 = new ComponentVersion(ecosystem, "1.1.0");
        ComponentVersion version_1_1_1 = new ComponentVersion(ecosystem, "1.1.1");
        ComponentVersion version_1_1_1b = new ComponentVersion(ecosystem, "1.1.1b");
        ComponentVersion version_1_1_1i = new ComponentVersion(ecosystem, "1.1.1i");
        ComponentVersion version_1_1_1j = new ComponentVersion(ecosystem, "1.1.1j");
        ComponentVersion version_1_1_1k = new ComponentVersion(ecosystem, "1.1.1k");
        ComponentVersion version_1_1_2 = new ComponentVersion(ecosystem, "1.1.2");

        // equality
        Assert.assertTrue(version_1_1_1j.compareTo(version_1_1_1j) == 0);
        Assert.assertTrue(version_1_1_1j.compareTo(version_1_1_1b) != 0);
        Assert.assertTrue(version_1_1_1j.compareTo(version_1_1_1) != 0);

        // less than
        Assert.assertTrue(version_1_1_1j.compareTo(version_1_1_2) < 0);
        Assert.assertTrue(version_1_1_1j.compareTo(version_1_1_1k) < 0);

        // greater than
        Assert.assertTrue(version_1_1_1j.compareTo(version_1_1_0) > 0);
        Assert.assertTrue(version_1_1_1j.compareTo(version_1_1_1i) > 0);
    }

    @Test
    public void testUbuntuOpensslVersion() {
        Ecosystem ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);
        ComponentVersion version_1_1_0 = new ComponentVersion(ecosystem, "1.1.0");
        ComponentVersion version_1_1_1 = new ComponentVersion(ecosystem, "1.1.1");
        ComponentVersion version_1_1_1b = new ComponentVersion(ecosystem, "1.1.1b");
        ComponentVersion version_1_1_1i = new ComponentVersion(ecosystem, "1.1.1i");
        ComponentVersion version_1_1_1j = new ComponentVersion(ecosystem, "1.1.1j");
        ComponentVersion version_1_1_1j_1ubuntu2_10 = new ComponentVersion(ecosystem, "1.1.1j-1ubuntu2.10");
        ComponentVersion version_1_1_1k = new ComponentVersion(ecosystem, "1.1.1k");
        ComponentVersion version_1_1_2 = new ComponentVersion(ecosystem, "1.1.2");

        // equality
        Assert.assertTrue(version_1_1_1j_1ubuntu2_10.compareTo(version_1_1_1j_1ubuntu2_10) == 0);
        Assert.assertTrue(version_1_1_1j_1ubuntu2_10.compareTo(version_1_1_1b) != 0);
        Assert.assertTrue(version_1_1_1j_1ubuntu2_10.compareTo(version_1_1_1) != 0);

        // less than
        Assert.assertTrue(version_1_1_1j_1ubuntu2_10.compareTo(version_1_1_2) < 0);
        Assert.assertTrue(version_1_1_1j_1ubuntu2_10.compareTo(version_1_1_1k) < 0);

        // greater than
        Assert.assertTrue(version_1_1_1j_1ubuntu2_10.compareTo(version_1_1_1j) > 0);
        Assert.assertTrue(version_1_1_1j_1ubuntu2_10.compareTo(version_1_1_0) > 0);
        Assert.assertTrue(version_1_1_1j_1ubuntu2_10.compareTo(version_1_1_1i) > 0);
    }

    @Test
    public void testDebian() {
        Ecosystem ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);

        List<String[]> list = new ArrayList<>();
        list.add(new String[]{"0+20131201.3459502-1.1","0.0.0-11build2"});
        list.add(new String[]{"0+git20190925.6d01903-0.1","2021.1~dfsg-2build2"});
        list.add(new String[]{"0.0.10","0.0.10-rc5+git20190411+3595f87-5"});
        list.add(new String[]{"0.002+source-5","0.10-1ubuntu0.22.04.3"});
        list.add(new String[]{"0.05-16+nmu2.1","0.5.1+dfsg+~cs3.2.4-2"});
        list.add(new String[]{"0.0~git20170619.f3a7b8f-2","2.3.0-49-g97d20249-1"});
        list.add(new String[]{"0.0~git20200204.15e6a9d+ds-3build1","0.0~hg1314+dfsg-1.1"});
        list.add(new String[]{"0.1+13.10.20130723-0ubuntu3","0.01-1-7"});
        list.add(new String[]{"1:0.9.6.2~0.22.04.8","1:0.9.6.2~0.22.04.8"});

        // Iterate over the list and print each array
        for (String[] version : list) {
            ComponentVersion version1 = new ComponentVersion(ecosystem, version[0]);
            ComponentVersion version2 = new ComponentVersion(ecosystem, version[1]);

            Assert.assertTrue(version1.compareTo(version2) <= 0);
        }

    }

    //@Test
    //@Disabled("Temporary disabled since test will run until the first error, in best case forever")
    public void testNpmRandomized()  {
        Ecosystem ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.GENERIC);

        String filePath = "src/test/resources/version/npm2.txt";
        List<String> lines = new ArrayList();

        try {
            lines = Files.readAllLines(Path.of(filePath));
        }
        catch (IOException e) {
            // Handle the exception
            System.err.println("An error occurred while reading the file:");
            e.printStackTrace();
        }

        Random random = new Random();

        while(true) {
        Integer firstPick = random.nextInt(lines.size());
        Integer secondPick = random.nextInt(lines.size());

        // Determine lesser and greater
        String lesser;
        String greater;

        if (firstPick.compareTo(secondPick) <= 0) {
            lesser = lines.get(firstPick);
            greater = lines.get(secondPick);
        } else {
            lesser = lines.get(secondPick);
            greater = lines.get(firstPick);
        }

        ComponentVersion version_lesser = new ComponentVersion(ecosystem, lesser);
        ComponentVersion version_greater = new ComponentVersion(ecosystem, greater);

        System.out.println(lesser +  "<<" + greater);
        Assert.assertTrue(version_lesser.compareTo(version_greater) <= 0);
        }
    }

    @Test
    public void testNpmFull()  {
        Ecosystem ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.GENERIC);

        String filePath = "src/test/resources/version/npm2.txt";
        List<String> lines = new ArrayList();

        try {
            lines = Files.readAllLines(Path.of(filePath));
        }
        catch (IOException e) {
            // Handle the exception
            System.err.println("An error occurred while reading the file:");
            e.printStackTrace();
        }

        for(Integer i=0; i<lines.size(); i++) {
            if((i%(lines.size()/100))==0) {
                System.out.println("testNpmFull: " + ((i*100)/lines.size()) + "%");
            }
            ComponentVersion version1 = new ComponentVersion(ecosystem, lines.get(i));
            for(Integer j=0; j<lines.size(); j++) {
                ComponentVersion version2 = new ComponentVersion(ecosystem, lines.get(j));

                // Custom message + speedup
                if(Math.signum(i.compareTo(j)) != Math.signum(version1.compareTo(version2)))
                {
                    Assert.assertTrue("Failing: " + version1.toString() + " " + version2.toString(), false);
                }
            }
        }
    }

    //@Test
    //@Disabled("Temporary disabled since test will run until the first error, in best case forever")
    public void testUbuntuRandomized()  {
        Ecosystem ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);

        String filePath = "src/test/resources/version/ubuntu2.txt";
        List<String> lines = new ArrayList();

        try {
            lines = Files.readAllLines(Path.of(filePath));
        }
        catch (IOException e) {
            // Handle the exception
            System.err.println("An error occurred while reading the file:");
            e.printStackTrace();
        }

        Random random = new Random();

        while(true) {
        Integer firstPick = random.nextInt(lines.size());
        Integer secondPick = random.nextInt(lines.size());

        // Determine lesser and greater
        String lesser;
        String greater;

        if (firstPick.compareTo(secondPick) <= 0) {
            lesser = lines.get(firstPick);
            greater = lines.get(secondPick);
        } else {
            lesser = lines.get(secondPick);
            greater = lines.get(firstPick);
        }

        ComponentVersion version_lesser = new ComponentVersion(ecosystem, lesser);
        ComponentVersion version_greater = new ComponentVersion(ecosystem, greater);

        System.out.println(lesser +  "<<" + greater);
        Assert.assertTrue(version_lesser.compareTo(version_greater) <= 0);
        }
    }

    @Test
    public void testUbuntuFull()  {
        Ecosystem ecosystem = EcosystemFactory.getEcosystem(PackageURL.StandardTypes.DEBIAN);

        String filePath = "src/test/resources/version/ubuntu2.txt";
        List<String> lines = new ArrayList();

        try {
            lines = Files.readAllLines(Path.of(filePath));
        }
        catch (IOException e) {
            // Handle the exception
            System.err.println("An error occurred while reading the file:");
            e.printStackTrace();
        }

        for(Integer i=0; i<lines.size(); i++) {
            if((i%(lines.size()/100))==0) {
                System.out.println("testUbuntuFull: " + ((i*100)/lines.size()) + "%");
            }
            ComponentVersion version1 = new ComponentVersion(ecosystem, lines.get(i));
            for(Integer j=0; j<lines.size(); j++) {
                ComponentVersion version2 = new ComponentVersion(ecosystem, lines.get(j));

                // Custom message + speedup
                if(Math.signum(i.compareTo(j)) != Math.signum(version1.compareTo(version2)))
                {
                    Assert.assertTrue("Failing: " + version1.toString() + " " + version2.toString(), false);
                }
            }
        }
    }




}

