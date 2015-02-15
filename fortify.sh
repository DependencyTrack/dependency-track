#!/bin/sh

# The location there the sourceanalyzer binary is located
SCAEXEC=/Applications/HP-Fortify/bin/sourceanalyzer

echo "Cleaning up"

# Deletes all SCA intermediate files and build records. When a build ID is also specified, only files and build records relating to that build ID are deleted.
$SCAEXEC -b DependencyTrack -clean 

echo "Performing SCA Translation"
# Performs a translate of the source files into normalized syntax tree format
$SCAEXEC -b DependencyTrack "src/main/**/*.js"
$SCAEXEC -b DependencyTrack "src/main/**/*.xml"
$SCAEXEC -b DependencyTrack "src/main/**/*.properties"
$SCAEXEC -b DependencyTrack -source 1.7 "src/main/**/*.jsp"
$SCAEXEC -b DependencyTrack -source 1.7 -cp "target/dtrack/WEB-INF/lib/*.jar" -sourcepath "target/sources" "src/main/**/*.java"

echo "Performing SCA Analysis"
# Perform an SCA analysis on the specified build id
$SCAEXEC -b DependencyTrack -scan -f results.fpr
