create table if not exists "PERSON" (
  "ID" int primary key generated always as identity
, "NAME" text
, "PROPERTIES" jsonb
, "UUID" TEXT
);