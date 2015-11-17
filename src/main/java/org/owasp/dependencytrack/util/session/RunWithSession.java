package org.owasp.dependencytrack.util.session;

import org.hibernate.Session;
import org.hibernate.SessionFactory;

public class RunWithSession
{
	public static<T> T  run(Session session, DBSessionTaskReturning<T> runnable){
		if(session != null){
				return runnable.run(session);
		}
		return null;
	}

	public static<T> T  run(SessionFactory sessionFactory, DBSessionTaskReturning<T> runnable){
		Session session = sessionFactory.getCurrentSession();
		boolean wasClosed = !session.isOpen();
		if (wasClosed){
			session = sessionFactory.openSession();
		}
		if(session != null){
			try{
				return runnable.run(session);
			}finally{
				if (wasClosed && session.isOpen()){
					session.close();
				}
			}
		}
		return null;
	}

	public static void run(SessionFactory sessionFactory, DBSessionTask runnable) {
		Session session = sessionFactory.getCurrentSession();
		boolean wasClosed = !session.isOpen();
		if (wasClosed) {
			session = sessionFactory.openSession();
		}
		if (session != null) {
			try {
				runnable.run(session);
			} finally {
				if (wasClosed && session.isOpen()) {
					session.close();
					if (wasClosed && session.isOpen()) {
						session.close();
					}
				}
			}
		}

	}
	
}
