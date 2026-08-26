UPDATE "NOTIFICATIONPUBLISHER"
   SET "NAME" = 'Microsoft Teams'
     , "DESCRIPTION" = 'Default Microsoft Teams publisher'
 WHERE "EXTENSION_NAME" = 'msteams'
   AND "DEFAULT_PUBLISHER" IS TRUE
   -- There's a UNIQUE index on "NAME", make sure to not violate that.
   AND NOT EXISTS (
     SELECT 1
       FROM "NOTIFICATIONPUBLISHER" AS other
      WHERE other."NAME" = 'Microsoft Teams'
   );
