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

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * PaginatedResult is a container class that provides a complete (or partial)
 * Collection (List/Set) of results along with the total number of results
 * for the query.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class PaginatedResult implements Serializable {

    private static final long serialVersionUID = 6944883925826545390L;

    private long total;
    private Collection objects;

    /**
     * Retrieves the total number of results.
     * @return the total number of results
     * @since 1.0.0
     */
    public long getTotal() {
        return total;
    }

    /**
     * Specifies the total number of results.
     * @param total the total number of results
     * @since 1.0.0
     */
    public void setTotal(long total) {
        this.total = total;
    }

    /**
     * Fluent. Specifies the total number of results.
     * @param total the total number of results
     * @return the current PaginatedResult instance
     * @since 1.0.0
     */
    public PaginatedResult total(long total) {
        this.total = total;
        return this;
    }


    /**
     * Retrieves a Collection of objects from the result.
     * @return a Collection of objects from the result.
     * @since 1.0.0
     */
    public Collection getObjects() {
        return objects;
    }

    /**
     * Retrieves a List of objects from the result.
     * @param <T> the type defined in the List
     * @param clazz the type defined in the List
     * @return a Collection of objects from the result.
     * @since 1.0.0
     */
    @SuppressWarnings("unchecked")
    public <T> List<T> getList(Class<T> clazz) {
        return (List<T>) objects;
    }

    /**
     * Retrieves a Set of objects from the result.
     * @param <T> the type defined in the Set
     * @param clazz the type defined in the Set
     * @return a Collection of objects from the result.
     * @since 1.0.0
     */
    @SuppressWarnings("unchecked")
    public <T> Set<T> getSet(Class<T> clazz) {
        return (Set<T>) objects;
    }

    /**
     * Specifies a Collection of objects from the result.
     * @param collection a Collection of objects from the result.
     * @since 1.0.0
     */
    public void setObjects(Collection<?> collection) {
        this.objects = collection;
    }

    /**
     * Fluent. Specifies a Collection of objects from the result.
     * @param collection a Collection of objects from the result.
     * @return the current PaginatedResult instance
     * @since 1.0.0
     */
    public PaginatedResult objects(Collection<?> collection) {
        this.objects = collection;
        return this;
    }

    /**
     * Specifies a Collection of objects from the result.
     * @param object a Collection of objects from the result.
     * @since 1.0.0
     */
    public void setObjects(Object object) {
        if (Collection.class.isAssignableFrom(object.getClass())) {
            this.objects = (Collection) object;
        }
    }

    /**
     * Fluent. Specifies a Collection of objects from the result.
     * @param object a Collection of objects from the result.
     * @return the current PaginatedResult instance
     * @since 1.0.0
     */
    public PaginatedResult objects(Object object) {
        setObjects(object);
        return this;
    }

}
