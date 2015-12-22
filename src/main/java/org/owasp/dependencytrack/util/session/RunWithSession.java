/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
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
		Session session = null;
		try{
			session = sessionFactory.getCurrentSession();
		}catch (Exception e){

		}
		boolean wasClosed = session==null || !session.isOpen();
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
		Session session = null;
		try {
			session = sessionFactory.getCurrentSession();
		}catch (Throwable t){

		}

		boolean manageSession = (session==null) || !session.isOpen();
		if (manageSession) {
			session = sessionFactory.openSession();
		}
		if (session != null) {
			try {
				runnable.run(session);
			}catch(Throwable t){
				t.printStackTrace();
			}
			finally {
				if( session != null && session.isOpen() ){
					session.flush();
					if ( manageSession ) {
						session.close();
					}

				}
			}
		}

	}
	
}
