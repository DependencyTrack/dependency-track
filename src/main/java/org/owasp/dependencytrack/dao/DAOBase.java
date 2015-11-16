package org.owasp.dependencytrack.dao;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class DAOBase
{

	/**
	 * The Hibernate SessionFactory
	 */
	@Autowired
	protected SessionFactory sessionFactory;

	protected <T> T dbRun(WithSessionRunnable<T> runner){
		return RunWithSession.run(sessionFactory,runner);
	}

}
