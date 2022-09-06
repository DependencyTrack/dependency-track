#!/usr/bin/env bash

# This is a non-production script which simply zeros out various log files.
# Executing this script prior to launching Dependency-Track in a development
# environment is the intended use-case.

echo -n > ~/.dependency-track/dependency-track.log
echo -n > ~/.dependency-track/dependency-track-audit.log
echo -n > ~/.dependency-track/server.log