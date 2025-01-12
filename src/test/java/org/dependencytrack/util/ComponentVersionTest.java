package org.dependencytrack.util;

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
    public void testSimple() {
        ComponentVersion version1 = new ComponentVersion("1.0.0");
        ComponentVersion version2 = new ComponentVersion("2.0.0");

        Assert.assertEquals(-1, version1.compareTo(version2));
    }
    /*
    @Test
    public void testComplex()  {
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

        ComponentVersion version_lesser = new ComponentVersion(lesser);
        ComponentVersion version_greater = new ComponentVersion(greater);

        System.out.println(lesser +  "<<" + greater);
        if(!(version_lesser.compareTo(version_greater) <= 0))
            System.out.println("<<<<<<<BUG!!!!!!!!!!!!!!!!!!!!!!");
        }
    }
    */
}

