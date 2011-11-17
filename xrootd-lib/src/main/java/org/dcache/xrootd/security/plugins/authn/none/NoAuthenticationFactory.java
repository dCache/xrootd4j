package org.dcache.xrootd.security.plugins.authn.none;

import org.dcache.xrootd.security.AuthenticationFactory;
import org.dcache.xrootd.security.AuthenticationHandler;
import org.dcache.xrootd.security.plugins.authn.InvalidHandlerConfigurationException;

/**
 * Dummy authentication factory that creates an authentication handler which
 * accepts all AuthenticationRequests
 *
 * @author tzangerl
 *
 */
public class NoAuthenticationFactory implements AuthenticationFactory
{
    @Override
    public AuthenticationHandler createHandler()
            throws InvalidHandlerConfigurationException
    {
        return new NoAuthenticationHandler();
    }
}
