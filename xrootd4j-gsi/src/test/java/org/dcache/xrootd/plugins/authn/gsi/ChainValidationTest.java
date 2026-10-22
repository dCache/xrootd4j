/**
 * Copyright (C) 2011-2026 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.plugins.authn.gsi;

import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_x509;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrError;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.ValidatorParams;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * The certificate chain presented by the peer must be validated against the
 * trusted CAs, with or without a proxy (pure cert/key authentication, GSI 10600).
 */
public class ChainValidationTest {

    private static KeyPair caKeys;
    private static X509Certificate ca;
    private static KeyPair userKeys;
    private static X509Certificate user;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private OpensslCertChainValidator validator;
    private Handler handler;

    private static class Handler extends GSIRequestHandler {

        Handler(GSICredentialManager credentialManager) {
            super(credentialManager);
        }

        @Override
        public int getProtocolVersion() {
            return PROTOCOL_VERSION;
        }

        @Override
        protected String getSyncCipherMode() {
            return SYNC_CIPHER_MODE_PADDED;
        }
    }

    @BeforeClass
    public static void setUpPki() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        caKeys = generateKeyPair();
        ca = certificate("CN=Test CA,O=Test,DC=org", caKeys.getPublic(),
              "CN=Test CA,O=Test,DC=org", caKeys, true);
        userKeys = generateKeyPair();
        user = certificate("CN=Test User,O=Test,DC=org", userKeys.getPublic(),
              "CN=Test CA,O=Test,DC=org", caKeys, false);
    }

    @Before
    public void setUp() throws Exception {
        File caDir = folder.newFolder("certificates");
        String hash = OpensslTruststoreHelper.getOpenSSLCAHash(
              ca.getSubjectX500Principal(), false);
        try (OutputStream out = new FileOutputStream(new File(caDir, hash + ".0"))) {
            CertificateUtils.saveCertificate(out, ca, CertificateUtils.Encoding.PEM);
        }

        ValidatorParams params = new ValidatorParams(
              new RevocationParameters(CrlCheckingMode.IGNORE,
                    new OCSPParametes(OCSPCheckingMode.IGNORE)),
              ProxySupport.ALLOW);
        validator = new OpensslCertChainValidator(caDir.getPath(), false,
              NamespaceCheckingMode.IGNORE, TimeUnit.HOURS.toMillis(1),
              params, false);

        Properties properties = new Properties();
        properties.setProperty("xrootd.gsi.ca.path", caDir.getPath());
        handler = new Handler(new GSICredentialManager(properties, null, validator));
    }

    @After
    public void tearDown() {
        validator.dispose();
    }

    @Test
    public void shouldAcceptEndEntityChain() throws Exception {
        X509Certificate[] chain = {user};

        assertArrayEquals(chain, handler.processRSAVerification(
              x509Buckets(chain), Optional.of(user.getPublicKey())));
    }

    @Test
    public void shouldAcceptProxyChain() throws Exception {
        X509Certificate[] chain = ProxyGenerator.generate(
              new ProxyCertificateOptions(new X509Certificate[]{user}),
              userKeys.getPrivate()).getCertificateChain();

        assertArrayEquals(chain, handler.processRSAVerification(
              x509Buckets(chain), Optional.empty()));
    }

    @Test
    public void shouldRejectSelfSignedCertificate() throws Exception {
        KeyPair keys = generateKeyPair();
        X509Certificate selfSigned = certificate("CN=Test User,O=Test,DC=org",
              keys.getPublic(), "CN=Test User,O=Test,DC=org", keys, false);

        assertRejected(selfSigned);
    }

    @Test
    public void shouldRejectCertificateFromUntrustedCa() throws Exception {
        KeyPair otherCaKeys = generateKeyPair();
        KeyPair keys = generateKeyPair();
        X509Certificate untrusted = certificate("CN=Test User,O=Test,DC=org",
              keys.getPublic(), "CN=Test CA,O=Test,DC=org", otherCaKeys, false);

        assertRejected(untrusted);
    }

    @Test
    public void shouldRejectCertificateFromCaWithSameName() throws Exception {
        KeyPair otherCaKeys = generateKeyPair();
        KeyPair keys = generateKeyPair();
        X509Certificate forged = certificate("CN=Test User,O=Test,DC=org",
              keys.getPublic(), "CN=Test CA,O=Test,DC=org", otherCaKeys, false);

        assertRejected(forged);
    }

    @Test
    public void shouldRejectChainIfValidatorFails() throws Exception {
        X509CertChainValidator failing = (X509CertChainValidator) Proxy.newProxyInstance(
              getClass().getClassLoader(), new Class<?>[]{X509CertChainValidator.class},
              (proxy, method, args) -> {
                  throw new NullPointerException("signingCert is null");
              });
        handler = new Handler(new GSICredentialManager(new Properties(), null, failing));

        assertRejected(user);
    }

    @Test(expected = InvalidKeyException.class)
    public void shouldRejectChainNotMatchingPublicKey() throws Exception {
        handler.processRSAVerification(x509Buckets(user),
              Optional.of(generateKeyPair().getPublic()));
    }

    private void assertRejected(X509Certificate... chain) throws Exception {
        try {
            handler.processRSAVerification(x509Buckets(chain), Optional.empty());
            fail("invalid chain accepted");
        } catch (XrootdException e) {
            assertEquals(kGSErrError, e.getError());
        }
    }

    private static Map<BucketType, GSIBucket> x509Buckets(X509Certificate... chain)
          throws Exception {
        Map<BucketType, GSIBucket> buckets = new EnumMap<>(BucketType.class);
        buckets.put(kXRS_x509,
              new StringBucket(kXRS_x509, CertUtil.chainToPEM(Arrays.asList(chain))));
        return buckets;
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(String subject, PublicKey key,
          String issuer, KeyPair issuerKeys, boolean isCa) throws Exception {
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
              new X500Principal(issuer), BigInteger.valueOf(now),
              new Date(now - TimeUnit.HOURS.toMillis(1)),
              new Date(now + TimeUnit.DAYS.toMillis(1)),
              new X500Principal(subject), key);
        builder.addExtension(Extension.basicConstraints, true,
              new BasicConstraints(isCa));
        builder.addExtension(Extension.keyUsage, true, isCa
              ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
              : new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        return new JcaX509CertificateConverter().getCertificate(builder.build(
              new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate())));
    }
}
