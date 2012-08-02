/**
 * Copyright (C) 2011,2012 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.gsi;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import static java.util.concurrent.TimeUnit.SECONDS;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.plugins.InvalidHandlerConfigurationException;
import org.globus.gsi.CertificateRevocationLists;
import org.globus.gsi.TrustedCertificates;
import org.globus.gsi.proxy.ProxyPathValidator;
import org.globus.gsi.proxy.ProxyPathValidatorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authentication factory that returns GSI security handlers. Initiates the
 * server-side certificate objects (host certificate, host key, trusted
 * certificates and CRLs) needed for the handler to perform its tasks.
 *
 * Thus the certificates and trust anchors can be cached for a configurable
 * time period. The configuration option controlling this caching is the
 * same as the one used in the SRM door.
 *
 * @author tzangerl
 *
 */
public class GSIAuthenticationFactory implements AuthenticationFactory
{
    private static final Logger _logger =
        LoggerFactory.getLogger(GSIAuthenticationFactory.class);

    private String _hostCertificatePath;
    private String _hostKeyPath;
    private String _caCertificatePath;

    private X509Certificate _hostCertificate;
    private PrivateKey _hostKey;
    private TrustedCertificates _trustedCerts;

    private long _hostCertRefreshInterval;
    private long _trustAnchorRefreshInterval;
    private long _hostCertRefreshTimestamp = 0;
    private long _trustAnchorRefreshTimestamp = 0;

    private ProxyPathValidator _proxyValidator = new ProxyPathValidator();
    private boolean _verifyHostCertificate;

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public GSIAuthenticationFactory(Properties properties)
    {
        _hostKeyPath =
            properties.getProperty("xrootd.gsi.hostcert.key");
        _hostCertificatePath =
            properties.getProperty("xrootd.gsi.hostcert.cert");
        _hostCertRefreshInterval =
            SECONDS.toMillis(Integer.parseInt(properties.getProperty("xrootd.gsi.hostcert.refresh")));
        _verifyHostCertificate =
            Boolean.parseBoolean(properties.getProperty("xrootd.gsi.hostcert.verify"));

        _caCertificatePath = properties.getProperty("xrootd.gsi.ca.path");
        _trustAnchorRefreshInterval =
            SECONDS.toMillis(Integer.parseInt(properties.getProperty("xrootd.gsi.ca.refresh")));
    }

    @Override
    public AuthenticationHandler createHandler()
        throws InvalidHandlerConfigurationException
    {
        CertificateRevocationLists crls =
            CertificateRevocationLists.getDefaultCertificateRevocationLists();

        try {
            loadTrustAnchors();
            loadServerCredentials(crls);
        } catch (ProxyPathValidatorException ppvex) {
            String msg = "Could not verify server certificate chain";
            throw new InvalidHandlerConfigurationException(msg, ppvex);
        } catch (GeneralSecurityException gssex) {
            String msg = "Could not load certificates/key due to security error";
            throw new InvalidHandlerConfigurationException(msg, gssex);
        } catch (IOException ioex) {
            String msg = "Could not read certificates/key from file-system";
            throw new InvalidHandlerConfigurationException(msg, ioex);
        }

        return new GSIAuthenticationHandler(_hostCertificate,
                                            _hostKey,
                                            _trustedCerts,
                                            crls);
    }

    /**
     * Reload the trusted certificates from the position specified in
     * caCertDir
     */
    private synchronized void loadTrustAnchors()
    {
        long timeSinceLastTrustAnchorRefresh = (System.currentTimeMillis() -
                _trustAnchorRefreshTimestamp);

        if (_trustedCerts == null ||
                (timeSinceLastTrustAnchorRefresh >= _trustAnchorRefreshInterval)) {
            _logger.info("CA certificate directory: {}", _caCertificatePath);
            _trustedCerts = TrustedCertificates.load(_caCertificatePath);

            _trustAnchorRefreshTimestamp = System.currentTimeMillis();
        }
    }

    private synchronized void loadServerCredentials(CertificateRevocationLists crls)
        throws CertificateException, IOException, NoSuchAlgorithmException,
            InvalidKeySpecException, ProxyPathValidatorException, NoSuchProviderException
    {
        long timeSinceLastServerRefresh =
            (System.currentTimeMillis() - _hostCertRefreshTimestamp);

        if (_hostCertificate == null || _hostKey == null ||
                (timeSinceLastServerRefresh >= _hostCertRefreshInterval)) {
            _logger.info("Time since last server cert refresh {}",
                      timeSinceLastServerRefresh);
            _logger.info("Loading server certificates. Current refresh " +
                      "interval: {} ms",
                      _hostCertRefreshInterval);
             loadHostCertificate();
             loadHostKey();

             if (_verifyHostCertificate) {
                 _logger.info("Verifying host certificate");
                 verifyHostCertificate(crls);
             }

             _hostCertRefreshTimestamp = System.currentTimeMillis();
        }
    }

    private void loadHostCertificate()
        throws CertificateException, IOException, NoSuchProviderException
    {
        InputStream fis = new FileInputStream(_hostCertificatePath);
        try {
            CertificateFactory cf =
                CertificateFactory.getInstance("X.509", "BC");
            _hostCertificate = (X509Certificate) cf.generateCertificate(fis);
        } finally {
            fis.close();
        }
    }

    private void loadHostKey()
        throws NoSuchAlgorithmException, IOException, InvalidKeySpecException
    {
        /* java's RSA KeyFactory needs keys in PKCS8 encoding. Use
         * BouncyCastle instead, as jGlobus does.
         */
        BufferedReader br = new BufferedReader(new FileReader(_hostKeyPath));
        KeyPair kp = (KeyPair) new PEMReader(br).readObject();
        _hostKey = kp.getPrivate();
    }

    /**
     * Check whether host certificate's certificate chain is trusted according
     * to jGlobus' proxy validation check
     * @throws ProxyPathValidatorException
     */
    private void verifyHostCertificate(CertificateRevocationLists crls)
        throws ProxyPathValidatorException
    {
        _proxyValidator.validate(new X509Certificate[] { _hostCertificate },
                                 _trustedCerts.getCertificates(),
                                 crls,
                                 _trustedCerts.getSigningPolicies());
    }
}
