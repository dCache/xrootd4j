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
package org.dcache.xrootd.security;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

public interface XrootdSecurityProtocol
{
    String SEC_PROTOCOL_PREFIX="P=";
    String AUTHN_PROTOCOL_PREFIX="&" + SEC_PROTOCOL_PREFIX;

    /**
     *  _______________________________________________________________________
     *  BUCKET TYPES
     *  _______________________________________________________________________
     */
    enum BucketType {
        kXRS_none           (0),        // end-of-vector
        kXRS_inactive       (1),        // inactive (dropped at serialization)
        kXRS_cryptomod      (3000),     // Name of crypto module to use
        kXRS_main           (3001),     // Main buffer
        kXRS_srv_seal       (3002),     // Server secrets sent back as they are
        kXRS_clnt_seal      (3003),     // Client secrets sent back as they are
        kXRS_puk            (3004),     // Public Key
        kXRS_cipher         (3005),     // Cipher
        kXRS_rtag           (3006),     // Random Tag
        kXRS_signed_rtag    (3007),     // Random Tag signed by the client
        kXRS_user           (3008),     // User name
        kXRS_host           (3009),     // Remote Host name
        kXRS_creds          (3010),     // Credentials (password, ...)
        kXRS_message        (3011),     // Message (null-terminated string)
        kXRS_srvID          (3012),     // Server unique ID
        kXRS_sessionID      (3013),     // Handshake session ID
        kXRS_version        (3014),     // Package version
        kXRS_status         (3015),     // Status code
        kXRS_localstatus    (3016),     // Status code(s) saved in sealed buffer
        kXRS_othercreds     (3017),     // Alternative creds (e.g. other crypto)
        kXRS_cache_idx      (3018),     // Cache entry index
        kXRS_clnt_opts      (3019),     // Client options, if any
        kXRS_error_code     (3020),     // Error code
        kXRS_timestamp      (3021),     // Time stamp
        kXRS_x509           (3022),     // X509 certificate
        kXRS_issuer_hash    (3023),     // Issuer hash
        kXRS_x509_req       (3024),     // X509 certificate request
        kXRS_cipher_alg     (3025),     // Cipher algorithm (list)
        kXRS_md_alg         (3026),     // MD algorithm (list)
        kXRS_afsinfo        (3027),     // AFS information
        kXRS_reserved       (3028);     // Reserved

        private static final Map<Integer, XrootdSecurityProtocol.BucketType> LOOKUP
                        = new HashMap<>();

        static {
            for(BucketType s : EnumSet.allOf(BucketType.class))
            {
                LOOKUP.put(s.getCode(), s);
            }
        }

        private final int code;

        BucketType( int code ) {
            this.code = code;
        }

        public int getCode() {
            return code;
        }

        public static BucketType get(int code) {
            return LOOKUP.get(code);
        }
    }

    /**
     *  _______________________________________________________________________
     *  XROOTD4J INTERNAL -- DETERMINE STEP
     *  _______________________________________________________________________
     */
    static String getClientStep(int step)
    {
        switch(step)
        {
            case kXGC_none: return "kXGC_none";
            case kXGC_certreq: return "kXGC_certreq";
            case kXGC_cert: return "kXGC_cert";
            case kXGC_sigpxy: return "kXGC_sigpxy";
            case kXGC_reserved: return "kXGC_reserved";
            default:
                return "unrecognized step: " + step;
        }
    }

    static String getServerStep(int step)
    {
        switch(step)
        {
            case kXGS_none: return "kXGS_none";
            case kXGS_init: return "kXGS_init";
            case kXGS_cert: return "kXGS_cert";
            case kXGS_pxyreq: return "kXGS_pxyreq";
            case kXGS_reserved: return "kXGS_reserved";
            default:
                return "unrecognized step: " + step;
        }
    }

    /**
     *  _______________________________________________________________________
     *  SERVER STATUS RESPONSE CODES
     *  _______________________________________________________________________
     */
    int     kgST_ok                     =  0;       // ok
    int     kgST_error                  = -1;       // error occurred
    int     kgST_more                   =  1;       // need more info

    /**
     *  _______________________________________________________________________
     *  HANDSHAKE OPTIONS
     *  _______________________________________________________________________
     */
    int     kOptsDlgPxy                 = 0x0001;   // Ask for a delegated proxy
    int     kOptsFwdPxy                 = 0x0002;   // Forward local proxy
    int     kOptsSigReq                 = 0x0004;   // Accept to sign delegated proxy
    int     kOptsSrvReq                 = 0x0008;   // Server request for delegated proxy
    int     kOptsPxFile                 = 0x0010;   // Save delegated proxies in file
    int     kOptsDelChn                 = 0x0020;   // Delete chain

    /**
     *  _______________________________________________________________________
     *  SERVER SECURITY VERSION
     *  _______________________________________________________________________
     */
    int     kXR_secver_0                = 0;

    /**
     *  _______________________________________________________________________
     *  SECURITY LEVELS
     *  _______________________________________________________________________
     */
    int     kXR_secNone                 = 0;
    int     kXR_secCompatible           = 1;
    int     kXR_secStandard             = 2;
    int     kXR_secIntense              = 3;
    int     kXR_secPedantic             = 4;

    /**
     *  _______________________________________________________________________
     *  SECURITY OPTIONS
     *  _______________________________________________________________________
     */
    byte    kXR_sec0Data                = 0x01;
    byte    kXR_secOFrce                = 0x02;     // apply signing requirements even if no encryption

    /**
     *  _______________________________________________________________________
     *  SIGNING ACTION
     *  _______________________________________________________________________
     */
    int     kXR_signIgnore              = 0;
    int     kXR_signLikely              = 1;
    int     kXR_signNeeded              = 2;

    /**
     *  _______________________________________________________________________
     *  SIGNING REQUEST OPTIONS
     *  _______________________________________________________________________
     */
    byte    kXR_nodata                  = 1;        // do not sign write data

    /**
     *  _______________________________________________________________________
     *  GSI - CLIENT PROCESSING STEPS
     *  _______________________________________________________________________
     */
    int     kXGC_none                   =  0;
    int     kXGC_certreq                = 1000;     // request server certificate
    int     kXGC_cert                   = 1001;     // packet with (proxy) certificate
    int     kXGC_sigpxy                 = 1002;     // packet with signed proxy certificate
    int     kXGC_reserved               = 1003;

    /**
     *  _______________________________________________________________________
     *  GSI - SERVER PROCESSING STEPS
     *  _______________________________________________________________________
     */
    int     kXGS_none                   = 0;
    int     kXGS_init                   = 2000;     // fake code used the first time
    int     kXGS_cert                   = 2001;     // packet with certificate
    int     kXGS_pxyreq                 = 2002;     // packet with proxy req to be signed
    int     kXGS_reserved               = 2003;

    /**
     *  _______________________________________________________________________
     *  GSI - SERVER ERROR CODES
     *  _______________________________________________________________________
     */
    int     kGSErrParseBuffer           = 10000;    // The received buffer could not be parsed
    int     kGSErrDecodeBuffer          = 10001;    // Not enough memory for the global buffer
    int     kGSErrBadProtocol           = 10003;    // Protocol ID does not match the expected one (gsi)
    int     kGSErrCreateBucket          = 10004;    // Bucket can not be created; type in message string
    int     kGSErrSerialBuffer          = 10007;    // Main buffer serialization fails
    int     kGSErrBadRndmTag            = 10011;    // Random tag check failed
    int     kGSErrNoCipher              = 10013;    // No cipher when expected
    int     kGSErrBadOpt                = 10015;    // Unrecognized step
    int     kGSErrNoBuffer              = 10019;    // No input parameters when expected
    int     kGSErrNoPublic              = 10021;    // Problem extracting public component of cipher
    int     kGSErrAddBucket             = 10022;    // Bucket can not be added; type in message string
    int     kGSErrInit                  = 10024;    // Error during protocol initialization
    int     kGSErrError                 = 10026;    // Generic error
}
