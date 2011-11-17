package org.dcache.xrootd.security.plugins.authn.none;

import java.util.Properties;

import org.dcache.xrootd.security.AuthenticationProvider;
import org.dcache.xrootd.security.AuthenticationFactory;

public class NoAuthenticationProvider implements AuthenticationProvider
{
    private final static String NAME = "none";

    @Override
    public AuthenticationFactory createFactory(String plugin, Properties properties)
    {
        return NAME.equals(plugin) ? new NoAuthenticationFactory() : null;
    }
}