/*
This statement changes the URL for Maven Central from using HTTP to HTTPS.
As of January 2020, Maven Central no longer accepts HTTP requests and will
respond with a 501. This prevents Java components from being analyzed for
being out-of-date.
*/

UPDATE "REPOSITORY" SET "URL" = 'https://repo1.maven.org/maven2/' WHERE "TYPE" = 'MAVEN' AND "IDENTIFIER" = 'central';
