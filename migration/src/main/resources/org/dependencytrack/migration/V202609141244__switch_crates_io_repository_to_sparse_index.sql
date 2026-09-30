UPDATE "REPOSITORY"
   SET "URL" = 'https://index.crates.io'
 WHERE "TYPE" = 'CARGO'
   AND "IDENTIFIER" = 'crates.io'
   AND "URL" = 'https://crates.io';
