package org.owasp.dependencytrack.util.session;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class DBSessionTaskRunner
{

	/**
	 * The Hibernate SessionFactory
	 */
	@Autowired
	protected SessionFactory sessionFactory;

	protected <T> T dbRun(DBSessionTaskReturning<T> runner){
		return RunWithSession.run(sessionFactory,runner);
	}

	protected void dbRun(DBSessionTask runner){
		RunWithSession.run(sessionFactory,runner);
	}

}
