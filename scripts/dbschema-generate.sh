#!/usr/bin/env bash

DEFAULT_OUTPUT="./schema.sql"
DEFAULT_DNPROPS="./scripts/dbschema-generate.datanucleus.properties"

function printHelp() {
  echo "Generate the database schema for Dependency-Track."
  echo ""
  echo "Usage: $0 [-o <OUTPUT_FILE>] [-p <PROPERTIES_FILE>]"
  echo "Options:"
  echo " -o   Set output path for the schema (default: $DEFAULT_OUTPUT)"
  echo " -p   Set path to DataNucleus properties (default: $DEFAULT_DNPROPS)"
  echo ""
  echo "This script uses the DataNucleus schema tool:"
  echo "  https://www.datanucleus.org/products/accessplatform/jdo/persistence.html#schematool"
  echo ""
}

while getopts ":h:o:p:" opt; do
  case $opt in
    o)
      output=$OPTARG
      ;;
    p)
      dnprops=$OPTARG
      ;;
    h)
      printHelp
      exit
      ;;
    *)
      printHelp
      exit
      ;;
  esac
done

mvn datanucleus:schema-create \
  -DpersistenceUnitName=Alpine \
  -Dprops="${dnprops:-$DEFAULT_DNPROPS}" \
  -DcompleteDdl=true \
  -DddlFile="${output:-$DEFAULT_OUTPUT}" \
  -Dlog4jConfiguration=./scripts/dbschema-generate.log4j.properties