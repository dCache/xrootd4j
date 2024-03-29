/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
 * 
 * This file is part of xrootd4j.
 * 
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.util;

import java.io.Serializable;

public class ProxyRequest<K extends Serializable, R extends Serializable>
      implements Serializable {

    private static final long serialVersionUID = -594333151002795805L;

    private K key;
    private String id;
    private R request;

    public ProxyRequest() {
    }

    public ProxyRequest(K key,
          String id,
          R request) {
        this.key = key;
        this.id = id;
        this.request = request;
    }

    public K getKey() {
        return key;
    }

    public String getId() {
        return id;
    }

    public R getRequest() {
        return request;
    }

    public void setKey(K key) {
        this.key = key;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setRequest(R request) {
        this.request = request;
    }
}
