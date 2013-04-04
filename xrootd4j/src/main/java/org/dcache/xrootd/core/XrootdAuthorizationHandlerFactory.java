/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.core;

import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.jboss.netty.channel.ChannelHandler;

public class XrootdAuthorizationHandlerFactory implements ChannelHandlerFactory
{
    private final AuthorizationFactory _factory;

    public XrootdAuthorizationHandlerFactory(AuthorizationFactory factory)
    {
        _factory = factory;
    }

    @Override
    public String getName()
    {
        return XrootdAuthorizationHandlerProvider.PREFIX + _factory.getName();
    }

    @Override
    public String getDescription()
    {
        return _factory.getDescription();
    }

    @Override
    public ChannelHandler createHandler()
    {
        return new XrootdAuthorizationHandler(_factory);
    }
}
