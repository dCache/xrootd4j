package org.dcache.xrootd.security;

import java.util.Properties;

/**
 * A factory loader class for AuthenticationFactory.
 *
 * Implementations of this interface are usually obtained through
 * Java's ServiceLoader mechanism.
 */
public interface AuthenticationProvider
{
    /**
     * Creates and returns a new AuthenticationFactory.
     *
     * @param plugin name identifying a partcular type of AuthenticationFactory
     * @param properties configuration values
     * @return AuthenticationFactory instance or null if the provider
     * does not provide a matching AuthenticationFactory
     */
    AuthenticationFactory createFactory(String plugin, Properties properties)
        throws Exception;
}
