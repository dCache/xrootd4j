/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with xrootd4j.  If not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;
import java.util.ServiceLoader;

import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.AuthenticationProvider;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.plugins.ChannelHandlerProvider;
import org.dcache.xrootd.plugins.ProxyDelegationClient;
import org.dcache.xrootd.plugins.ProxyDelegationClientFactory;

public class XrootdAuthenticationHandlerProvider implements ChannelHandlerProvider
{
    private static final Logger _log =
        LoggerFactory.getLogger(XrootdAuthenticationHandlerProvider.class);

    static final String PREFIX = "authn:";

    private static ClassLoader _classLoader;

    public static void setPluginClassLoader(ClassLoader classLoader)
    {
        _classLoader = classLoader;
    }

    @Override
    public ChannelHandlerFactory createFactory(String plugin, Properties properties) throws Exception
    {
        if (plugin.startsWith(PREFIX)) {
            String name = plugin.substring(PREFIX.length());
            AuthenticationFactory authnFactory = createAuthnFactory(name,
                                                                    properties);

            if (authnFactory != null) {
                ProxyDelegationClient client = createClient(name, properties);
                return new XrootdAuthenticationHandlerFactory(name,
                                                              authnFactory,
                                                              client);
            }
        }
        return null;
    }

    private AuthenticationFactory createAuthnFactory(String name, Properties properties)
                    throws Exception
    {
        ServiceLoader<AuthenticationProvider> providers = (_classLoader == null)
                        ? ServiceLoader.load(AuthenticationProvider.class)
                        : ServiceLoader.load(AuthenticationProvider.class, _classLoader);

        for (AuthenticationProvider provider: providers) {
            AuthenticationFactory factory = provider.createFactory(name, properties);
            if (factory != null) {
                _log.debug("AuthenticationHandler plugin {} is provided by {}", name, provider.getClass());
                return factory;
            } else {
                _log.debug("AuthenticationHandler plugin {} could not be provided by {}", name,
                           provider.getClass());
            }
        }

        return null;
    }

    private ProxyDelegationClient createClient(String name, Properties properties)
                    throws Exception
    {
        ServiceLoader<ProxyDelegationClientFactory> factories = (_classLoader == null)
                        ? ServiceLoader.load(ProxyDelegationClientFactory.class)
                        : ServiceLoader.load(ProxyDelegationClientFactory.class, _classLoader);

        for (ProxyDelegationClientFactory factory: factories) {
            ProxyDelegationClient client = factory.createClient(name, properties);
            if (client != null) {
                _log.debug("Creating a credential store client for {} using {}.",
                           name, factory.getClass());
                return client;
            }
        }

        return null;
    }
}
