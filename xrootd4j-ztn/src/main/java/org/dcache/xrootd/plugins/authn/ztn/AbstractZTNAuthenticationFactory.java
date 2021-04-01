/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.ztn;

import com.google.common.base.Strings;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.dcache.xrootd.plugins.AuthenticationFactory;

/**
 * Authentication factory that returns ztn authentication handlers.
 */
public abstract class AbstractZTNAuthenticationFactory implements AuthenticationFactory
{
    private static final String MAX_TOKEN_SZ = "xrootd.plugin!ztn.max-token-len-in-bytes";
    private static final String TOKEN_FLAGS = "xrootd.plugin!ztn.token-flags";
    private static final String ALT_TOKEN_LOCS = "xrootd.plugin!ztn.alt-token-locs";

    protected Integer      maxTokenSize;
    protected Long         tokenUsageFlags;
    protected List<String> alternateTokenLocations;

    protected AbstractZTNAuthenticationFactory(Properties properties)
                    throws ClassNotFoundException
    {
        String property = Strings.emptyToNull(properties.getProperty(MAX_TOKEN_SZ));
        if (property != null) {
            maxTokenSize = Integer.valueOf(property);
        }

        property = Strings.emptyToNull(properties.getProperty(TOKEN_FLAGS));
        if (property != null) {
            tokenUsageFlags = Long.valueOf(property);
        }

        property = Strings.emptyToNull(properties.getProperty(ALT_TOKEN_LOCS));
        if (property != null) {
            alternateTokenLocations = Arrays.asList(property.split(","));
        }
    }
}
