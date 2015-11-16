package org.owasp.dependencytrack.dao;

import org.hibernate.Session;

public interface WithSessionRunnable<T>
{
	T runWithSession(Session session);
}
