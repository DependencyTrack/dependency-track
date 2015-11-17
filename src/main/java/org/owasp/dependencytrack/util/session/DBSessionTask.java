package org.owasp.dependencytrack.util.session;

import org.hibernate.Session;

/**
 * Created by jason on 17/11/15.
 */
public interface DBSessionTask {
    void run(Session session);
}
