package org.dcache.xrootd.security.plugins.authz;

import java.util.Properties;

import org.dcache.xrootd.security.AuthorizationProvider;
import org.dcache.xrootd.security.AuthorizationFactory;

import com.google.common.collect.ImmutableSet;

public class NoAuthorizationProvider implements AuthorizationProvider
{
    private final static ImmutableSet<String> PLUGINS =
        ImmutableSet.of(NoAuthorizationFactory.NAME,
                        "org.dcache.xrootd.security.plugins.tokenauthz.NoAuthorizationFactory");

    @Override
    public AuthorizationFactory createFactory(String plugin, Properties properties)
    {
        return PLUGINS.contains(plugin) ? new NoAuthorizationFactory() : null;
    }
}