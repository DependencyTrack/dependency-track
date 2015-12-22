package org.owasp.dependencytrack.repository;

import org.owasp.dependencytrack.model.Library;
import org.springframework.data.repository.CrudRepository;

/**
 * Created by Jason Wraxall on 8/12/15.
 */
public interface LibraryRepository extends CrudRepository<Library,Long> {
}
