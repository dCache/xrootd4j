package org.dcache.xrootd.security;

import org.dcache.xrootd.security.plugins.authn.InvalidHandlerConfigurationException;

public interface AuthenticationFactory
{
    public AuthenticationHandler createHandler()
        throws InvalidHandlerConfigurationException;
}
