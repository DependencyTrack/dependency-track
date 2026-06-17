/**
 * Function to generate UUIDv7 values with millisecond precision.
 * This implementation has been sourced from github.com/dverite/postgres-uuidv7-sql.
 *
 * The function name is prefixed with odt_ (*O*WASP *D*ependency-*T*rack) to prevent
 * conflicts with the native uuidv7 function in PostgreSQL 18 and later.
 */
CREATE OR REPLACE FUNCTION odt_uuidv7(timestamptz DEFAULT clock_timestamp()) RETURNS uuid
AS $$
  -- Replace the first 48 bits of a uuidv4 with the current
  -- number of milliseconds since 1970-01-01 UTC
  -- and set the "ver" field to 7 by setting additional bits
  select encode(
    set_bit(
      set_bit(
        overlay(uuid_send(gen_random_uuid()) placing
	  substring(int8send((extract(epoch from $1)*1000)::bigint) from 3)
	  from 1 for 6),
	52, 1),
      53, 1), 'hex')::uuid;
$$ LANGUAGE sql volatile parallel safe;