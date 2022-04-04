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

import java.util.Properties;

/**
 * A factory class for ProxyDelegationClientFactory.
 *
 * Implementations of this interface are usually obtained through
 * Java's ServiceLoader mechanism.
 */
public interface ProxyDelegationClientFactory<C extends ProxyDelegationClient> {

    /**
     * Creates and returns a new ProxyDelegationClient
     *
     * @param authPlugin name identifying a particular type of AuthenticationFactory.
     * @param properties configuration values
     * @return ProxyDelegationClientFactory instance or null if the provider
     * does not provide a matching AuthenticationFactory
     */
    C createClient(String authPlugin, Properties properties)
          throws InvalidHandlerConfigurationException;
}
