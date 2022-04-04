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

import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.plugins.AuthorizationProvider;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.plugins.ChannelHandlerProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;
import java.util.ServiceLoader;

public class XrootdAuthorizationHandlerProvider implements ChannelHandlerProvider
{
    private static final Logger _log =
        LoggerFactory.getLogger(XrootdAuthorizationHandlerProvider.class);

    static final String PREFIX = "authz:";

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

            ServiceLoader<AuthorizationProvider> providers = (_classLoader == null)
                ? ServiceLoader.load(AuthorizationProvider.class)
                : ServiceLoader.load(AuthorizationProvider.class, _classLoader);
            for (AuthorizationProvider provider: providers) {
                AuthorizationFactory factory = provider.createFactory(name, properties);
                if (factory != null) {
                    _log.debug("AuthorizationHandler plugin {} is provided by {}", name, provider.getClass());
                    return new XrootdAuthorizationHandlerFactory(factory);
                } else {
                    _log.debug("AuthorizationHandler plugin {} could not be provided by {}", name,
                        provider.getClass());
                }
            }
        }
        return null;
    }
}
