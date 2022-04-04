/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins;

import java.io.Serializable;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.util.ProxyRequest;

/**
 * An internal interface which should be implemented by the code
 * referencing this library in order to cache delegated credentials.
 *
 * @param <C>
 */
public interface ProxyDelegationClient<C extends Serializable,
      K extends Serializable,
      P extends Serializable,
      R extends Serializable> {

    /**
     * @param request current request to cancel
     */
    void cancelProxyRequest(ProxyRequest<K, R> request) throws XrootdException;

    /**
     * @param id of the stored credential; this is the field of the
     *           ProxyRequest returned by #getProxyRequest.
     * @param proxyCert the proxy certificate
     * @return the full proxy credential
     * @throws XrootdException
     */
    C finalizeProxyCredential(String id, P proxyCert)
          throws XrootdException;

    /**
     * @param key object containing the necessary identifying attributes
     * @parma primaryFqan for the credential, if there is one
     * @return request to send to client.
     */
    ProxyRequest<K, R> getProxyRequest(K key)
          throws XrootdException;

    /**
     * Clean up any resources used by the client.
     */
    void close();
}
