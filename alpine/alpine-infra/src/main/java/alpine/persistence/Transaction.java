/*
 * This file is part of Alpine.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.persistence;

import javax.jdo.Constants;
import javax.jdo.PersistenceManager;
import java.util.ArrayList;
import java.util.concurrent.Callable;

public final class Transaction {

    public enum Isolation {

        READ_UNCOMMITTED,
        READ_COMMITTED,
        REPEATABLE_READ,
        SNAPSHOT,
        SERIALIZABLE;

        private String jdoName() {
            return switch (this) {
                case READ_UNCOMMITTED -> Constants.TX_READ_UNCOMMITTED;
                case READ_COMMITTED -> Constants.TX_READ_COMMITTED;
                case REPEATABLE_READ -> Constants.TX_REPEATABLE_READ;
                case SNAPSHOT -> Constants.TX_SNAPSHOT;
                case SERIALIZABLE -> Constants.TX_SERIALIZABLE;
            };
        }

        private static Isolation fromJdoName(final String jdoName) {
            return switch (jdoName) {
                case Constants.TX_READ_UNCOMMITTED -> READ_UNCOMMITTED;
                case Constants.TX_READ_COMMITTED -> READ_COMMITTED;
                case Constants.TX_REPEATABLE_READ -> REPEATABLE_READ;
                case Constants.TX_SNAPSHOT -> SNAPSHOT;
                case Constants.TX_SERIALIZABLE -> SERIALIZABLE;
                default -> throw new IllegalArgumentException("Unknown isolation: %s".formatted(jdoName));
            };
        }

    }

    public enum Propagation {
        REQUIRED,
        REQUIRES_NEW
    }

    public static class Options {

        private Isolation isolation;
        private Propagation propagation;
        private Boolean serializeRead;

        public Options withIsolation(final Isolation isolation) {
            this.isolation = isolation;
            return this;
        }

        public Options withPropagation(final Propagation propagation) {
            this.propagation = propagation;
            return this;
        }

        public Options withSerializeRead(final boolean serializeRead) {
            this.serializeRead = serializeRead;
            return this;
        }

    }

    private Transaction() {
    }

    public static Options defaultOptions() {
        return new Options();
    }

    public static <T> T call(final PersistenceManager pm, final Options options, final Callable<T> callable) {
        final javax.jdo.Transaction jdoTransaction = pm.currentTransaction();

        // A PersistenceManager's currentTransaction is not reset upon commit or rollback.
        // Changes made to a transaction object will persist until the owning PM is closed.
        // Ensure we're doing our best to leave the transaction as we found it.
        final var cleanups = new ArrayList<Runnable>();
        try {
            final boolean isJoiningExisting = jdoTransaction.isActive();
            if (isJoiningExisting && options.propagation == Propagation.REQUIRES_NEW) {
                throw new IllegalStateException("Propagation is set to %s, but a transaction is already active"
                        .formatted(Propagation.REQUIRES_NEW));
            }

            final Isolation currentIsolation = Isolation.fromJdoName(jdoTransaction.getIsolationLevel());
            final Isolation requestedIsolation = options.isolation;
            if (requestedIsolation != null && currentIsolation != requestedIsolation) {
                if (isJoiningExisting) {
                    throw new IllegalStateException("""
                            Requested isolation is %s, but transaction is already \
                            active with isolation %s""".formatted(requestedIsolation, currentIsolation));
                }

                cleanups.add(() -> jdoTransaction.setIsolationLevel(currentIsolation.jdoName()));
                jdoTransaction.setIsolationLevel(requestedIsolation.jdoName());
            }

            final Boolean currentSerializeRead = jdoTransaction.getSerializeRead();
            final Boolean requestedSerializeRead = options.serializeRead;
            if (requestedSerializeRead != null && currentSerializeRead != requestedSerializeRead) {
                if (isJoiningExisting) {
                    throw new IllegalStateException("""
                            Requested serializeRead=%s, but transaction is already \
                            active with serializeRead=%s""".formatted(requestedSerializeRead, currentSerializeRead));
                }

                cleanups.add(() -> jdoTransaction.setSerializeRead(currentSerializeRead));
                jdoTransaction.setSerializeRead(requestedSerializeRead);
            }

            try {
                if (!isJoiningExisting) {
                    jdoTransaction.begin();
                }

                final T result = callable.call();

                if (!isJoiningExisting) {
                    jdoTransaction.commit();
                }

                return result;
            } catch (Exception e) {
                if (e instanceof final RuntimeException re) {
                    // Avoid unnecessary wrapping if we're
                    // already dealing with a RuntimeException.
                    throw re;
                }

                throw new RuntimeException(e);
            } finally {
                if (jdoTransaction.isActive() && !isJoiningExisting) {
                    jdoTransaction.rollback();
                }
            }
        } finally {
            cleanups.forEach(Runnable::run);
        }
    }

}
