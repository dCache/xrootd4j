/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authz.none;

import java.util.Properties;

import org.dcache.xrootd.plugins.AuthorizationProvider;
import org.dcache.xrootd.plugins.AuthorizationFactory;

import com.google.common.collect.ImmutableSet;

public class NoAuthorizationProvider implements AuthorizationProvider
{
    private static final ImmutableSet<String> PLUGINS =
        ImmutableSet.of(NoAuthorizationFactory.NAME,
                        "org.dcache.xrootd.security.plugins.tokenauthz.NoAuthorizationFactory");

    @Override
    public AuthorizationFactory createFactory(String plugin, Properties properties)
    {
        return PLUGINS.contains(plugin) ? new NoAuthorizationFactory() : null;
    }
}
