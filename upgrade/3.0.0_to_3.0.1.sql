/*
Removes the constraint on having a unique project name thus preventing
multiple versions of the project from existing.
https://github.com/DependencyTrack/dependency-track/issues/118
*/
ALTER TABLE PROJECT DROP CONSTRAINT PROJECT_NAME_IDX;