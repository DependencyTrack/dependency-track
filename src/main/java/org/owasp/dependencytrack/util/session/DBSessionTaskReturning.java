package org.owasp.dependencytrack.util.session;

import org.hibernate.Session;

public interface DBSessionTaskReturning<T>
{
	T run(Session session);
}
