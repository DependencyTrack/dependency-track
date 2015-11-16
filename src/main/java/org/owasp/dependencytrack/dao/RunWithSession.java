package org.owasp.dependencytrack.dao;

import org.hibernate.Session;
import org.hibernate.SessionFactory;

public class RunWithSession<T>
{
	public static<T> T  run(Session session, WithSessionRunnable<T> runnable){
		if(session != null){
			try{
				return runnable.runWithSession(session);
			}finally{
				session.close();
			}
		}
		return null;
	}

	public static<T> T  run(SessionFactory sessionFactory, WithSessionRunnable<T> runnable){
		Session session = sessionFactory.openSession();
		if(session != null){
			try{
				return runnable.runWithSession(session);
			}finally{
				if(session.isOpen()){
					session.close();
				}
			}
		}
		return null;
	}
	
}
