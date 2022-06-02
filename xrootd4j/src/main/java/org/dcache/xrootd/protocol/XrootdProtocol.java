/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.protocol;

public interface XrootdProtocol {
    /*
     *  _______________________________________________________________________
     *  AUTHZ
     *
     *  Access permissions when using xrootd authz.
     *  A file can have only one type (no combinations);
     *  the granted rights increase in the order of appereance
     *  (e.g. delete includes write, which includes read and write-once).
     *  _______________________________________________________________________
     */
    enum FilePerm
    {
        READ ("read"),
        WRITE_ONCE ("write-once"),
        WRITE ("write"),
        DELETE ("delete");

        private final String _xmlText;

        FilePerm(String xmlText) {
            _xmlText = xmlText;
        }

        public String xmlText() { return _xmlText; }
    }

    /**
     *  _______________________________________________________________________
     *  XROOTD4J INTERNALS
     *  _______________________________________________________________________
     */
    int     DEFAULT_PORT                = 1094;
    byte    CLIENT_REQUEST_LEN          = 24;
    byte    CLIENT_HANDSHAKE_LEN        = 20;
    byte    SERVER_RESPONSE_LEN         = 8;
    int     SESSION_ID_SIZE             = 16;
    byte    OPAQUE_DELIMITER            = (byte) 0x3f;

    /*
     *  Passed from door to pool to identify transfer.
     */
    String  UUID_PREFIX                 = "org.dcache.uuid";

    /**
     *  _______________________________________________________________________
     *  VERSIONING
     *
     *  Protocol version is represented as three base10 digits x.y.z with x
     *  having no upper limit (i.e. n.9.9 + 1 -> n+1.0.0).
     *
     *  PROTOCOL_SIGN_VERSION defines the protocol version where request
     *  signing became available.
     *  _______________________________________________________________________
     */
    int     PROTOCOL_VERSION            = 0x00000500;
    int     PROTOCOL_SIGN_VERSION       = 0x00000310;
    int     PROTOCOL_TLS_VERSION        = 0x00000500;
    byte    PROTOCOL_VERSION_MAJOR      = (byte) ((PROTOCOL_VERSION & 0xFF00) >> 8);
    byte    PROTOCOL_VERSION_MINOR      = (byte) (PROTOCOL_VERSION & 0x00FF);
    int     TPC_VERSION                 = 1;


    /**
     *  _______________________________________________________________________
     *  SERVER TYPE
     *
     *  Flag values in the kXR_protocol response.
     *  Defined for protocol version 2.9.7 or higher.
     *
     *  (see further below for other PROTOCOL RESPONSE flags)
     *  _______________________________________________________________________
     */
    int     kXR_LBalServer              = 0x00000000;
    int     kXR_DataServer              = 0x00000001;
    int     kXR_isManager               = 0x00000002;
    int     kXR_isServer                = 0x00000001;
    int     kXR_attrMeta                = 0x00000100;
    int     kXR_attrProxy               = 0x00000200;
    int     kXR_attrSuper               = 0x00000400;

    /**
     *  _______________________________________________________________________
     *  KINDS OF SERVERS -- for backward compatibility
     *  _______________________________________________________________________
     */
    int     LOAD_BALANCER               = kXR_LBalServer;
    int     DATA_SERVER                 = kXR_DataServer;

    /**
     *  _______________________________________________________________________
     *  HANDSHAKE
     *  _______________________________________________________________________
     */
    byte[]  HANDSHAKE_REQUEST =
                    {
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 4, 0, 0, 7, (byte) 220
                    };

    byte[]  HANDSHAKE_RESPONSE_LOADBALANCER =
                    {
                                    0, 0, 0, 0, 0, 0, 0, 8, 0, 0,
                                    PROTOCOL_VERSION_MAJOR,
                                    PROTOCOL_VERSION_MINOR,
                                    0, 0, 0, LOAD_BALANCER
                    };

    byte[]  HANDSHAKE_RESPONSE_DATASERVER =
                    {
                                    0, 0, 0, 0, 0, 0, 0, 8, 0, 0,
                                    PROTOCOL_VERSION_MAJOR,
                                    PROTOCOL_VERSION_MINOR,
                                    0, 0, 0, DATA_SERVER
                    };

    /**
     *  _______________________________________________________________________
     *  CLIENT REQUEST TYPES
     *  _______________________________________________________________________
     */
    int     kXR_handshake               = 0;
    int     kXR_auth                    = 3000;
    int     kXR_query                   = 3001;
    int     kXR_chmod                   = 3002;
    int     kXR_close                   = 3003;
    int     kXR_dirlist                 = 3004;
    int     kXR_gpfile                  = 3005; // was kXR_getfile
    int     kXR_protocol                = 3006;
    int     kXR_login                   = 3007;
    int     kXR_mkdir                   = 3008;
    int     kXR_mv                      = 3009;
    int     kXR_open                    = 3010;
    int     kXR_ping                    = 3011;
    int     kXR_chkpoint                = 3012; // was kXR_putfile
    int     kXR_read                    = 3013;
    int     kXR_rm                      = 3014;
    int     kXR_rmdir                   = 3015;
    int     kXR_sync                    = 3016;
    int     kXR_stat                    = 3017;
    int     kXR_set                     = 3018;
    int     kXR_write                   = 3019;
    int     kXR_fattr                   = 3020; // was kXR_admin
    int     kXR_prepare                 = 3021;
    int     kXR_statx                   = 3022;
    int     kXR_endsess                 = 3023;
    int     kXR_bind                    = 3024;
    int     kXR_readv                   = 3025;
    int     kXR_pgwrite                 = 3026; // was kXR_verifyw
    int     kXR_locate                  = 3027;
    int     kXR_truncate                = 3028;
    int     kXR_sigver                  = 3029;
    int     kXR_pgread                  = 3030; // was kXR_decrypt
    int     kXR_writev                  = 3031;
    int     kXR_REQFENCE                = 3032;

    static String getClientRequest(int code) {
        switch (code) {
            case kXR_handshake: return "kXR_handshake";
            case kXR_auth: return "kXR_auth";
            case kXR_query: return "kXR_query";
            case kXR_chmod: return "kXR_chmod";
            case kXR_close: return "kXR_close";
            case kXR_dirlist: return "kXR_dirlist";
            case kXR_gpfile: return "kXR_gpfile";
            case kXR_protocol: return "kXR_protocol";
            case kXR_login: return "kXR_login";
            case kXR_mkdir: return "kXR_mkdir";
            case kXR_mv: return "kXR_mv";
            case kXR_open: return "kXR_open";
            case kXR_ping: return "kXR_ping";
            case kXR_chkpoint: return "kXR_chkpoint";
            case kXR_read: return "kXR_read";
            case kXR_rm: return "kXR_rm";
            case kXR_rmdir: return "kXR_rmdir";
            case kXR_sync: return "kXR_sync";
            case kXR_stat: return "kXR_stat";
            case kXR_set: return "kXR_set";
            case kXR_write: return "kXR_write";
            case kXR_fattr: return "kXR_fattr";
            case kXR_prepare: return "kXR_prepare";
            case kXR_statx: return "kXR_statx";
            case kXR_endsess: return "kXR_endsess";
            case kXR_bind: return "kXR_bind";
            case kXR_readv: return "kXR_readv";
            case kXR_pgwrite: return "kXR_pgwrite";
            case kXR_locate: return "kXR_locate";
            case kXR_truncate: return "kXR_truncate";
            case kXR_sigver: return "kXR_sigver";
            case kXR_pgread: return "kXR_pgread";
            case kXR_writev: return "kXR_writev";
            case kXR_REQFENCE: return "kXR_REQFENCE";
            default:
                return "unrecognized client request";
        }
    }


    /**
     *  _______________________________________________________________________
     *  OPEN MODE FOR A REMOTE FILE
     *  _______________________________________________________________________
     */
    int     kXR_ur                      = 0x100;
    int     kXR_uw                      = 0x080;
    int     kXR_ux                      = 0x040;
    int     kXR_gr                      = 0x020;
    int     kXR_gw                      = 0x010;
    int     kXR_gx                      = 0x008;
    int     kXR_or                      = 0x004;
    int     kXR_ow                      = 0x002;
    int     kXR_ox                      = 0x001;

    /**
     *  _______________________________________________________________________
     *  MKDIR OPTIONS
     *  _______________________________________________________________________
     */
    int     kXR_mknone                  = 0;
    int     kXR_mkdirpath               = 1;

    /**
     *  _______________________________________________________________________
     *  LOGIN CAPABILITY
     *  _______________________________________________________________________
     */
    int     kXR_nothing                 =   0;
    int     kXR_fullurl                 =   1;
    int     kXR_multipr                 =   3;
    int     kXR_readrdok                =   4;
    int     kXR_hasipv64                =   8;
    int     kXR_onlyprv4                =  16;
    int     kXR_onlyprv6                =  32;
    int     kXR_lclfile                 =  64;

    /**
     *  _______________________________________________________________________
     *  LOGIN CAPABILITY VERSION
     *  _______________________________________________________________________
     */
    int     kXR_lcvnone                 = 0;
    int     kXR_vermask                 = 63;
    int     kXR_asyncap                 = 128;

    /**
     *  _______________________________________________________________________
     *  a single number that goes into capver as the version
     *  _______________________________________________________________________
     */
    int     kXR_ver000                  = 0; // Old clients predating history
    int     kXR_ver001                  = 1; // Generally implemented 2005 protocol
    int     kXR_ver002                  = 2; // Same as 1 but adds asyncresp recognition
    int     kXR_ver003                  = 3; // The 2011-2012 rewritten client
    int     kXR_ver004                  = 4; // The 2016 sign-capable client
    int     kXR_ver005                  = 5; // The 2019 TLS-capable    client

    /**
     *  _______________________________________________________________________
     *  STAT REQUEST OPTIONS
     *  _______________________________________________________________________
     */
    int     kXR_vfs                     = 1;

    /**
     *  _______________________________________________________________________
     *  STAT RESPONSE FLAGS
     *  _______________________________________________________________________
     */
    int     kXR_file                    = 0x00;
    int     kXR_xset                    = 0x01;
    int     kXR_isDir                   = 0x02;
    int     kXR_other                   = 0x04;
    int     kXR_offline                 = 0x08;
    int     kXR_readable                = 0x10;
    int     kXR_writable                = 0x20;
    int     kXR_poscpend                = 0x40;
    int     kXR_bkpexist                = 0x80;

    /**
     *  _______________________________________________________________________
     *  DIR LIST REQUEST OPTIONS
     *  _______________________________________________________________________
     */
    int     kXR_online                  = 1;
    int     kXR_dstat                   = 2;

    /**
     *  _______________________________________________________________________
     *  OPEN REQUEST OPTIONS
     *  _______________________________________________________________________
     */
    int     kXR_compress                = 0x0001;
    int     kXR_delete                  = 0x0002;
    int     kXR_force                   = 0x0004;
    int     kXR_new                     = 0x0008;
    int     kXR_open_read               = 0x0010;
    int     kXR_open_updt               = 0x0020;
    int     kXR_async                   = 0x0040;
    int     kXR_refresh                 = 0x0080;  // also locate
    int     kXR_mkpath                  = 0x0100;
    int     kXR_prefname                = 0x0100;  // only locate
    int     kXR_open_apnd               = 0x0200;
    int     kXR_retstat                 = 0x0400;
    int     kXR_replica                 = 0x0800;
    int     kXR_posc                    = 0x1000;
    int     kXR_nowait                  = 0x2000;  // also locate
    int     kXR_seqio                   = 0x4000;
    int     kXR_open_wrto               = 0x8000;

    @Deprecated // Kept for compatibility with plugins
    int     kXR_opscpend                = 0x0040;

    /**
     *  _______________________________________________________________________
     *  PROTOCOL REQUEST FLAGS
     *  _______________________________________________________________________
     */
    byte    kXR_secreqs                 = 0x01;
    byte    kXR_ableTLS                 = 0x02;
    byte    kXR_wantTLS                 = 0x04;

    /**
     *  _______________________________________________________________________
     *  PROTOCOL REQUEST EXPECT
     *  _______________________________________________________________________
     */
    byte    kXR_expMask                 = 0x0f;  // to isolate expect encoding
    byte    kXR_ExpNone                 = 0x00;  // No expectations
    byte    kXR_ExpBind                 = 0x01;  // expect a kXR_bine request
    byte    kXR_ExpGPF                  = 0x02;  // expect a kXR_gpfile request
    byte    kXR_ExpGPFA                 = 0x20;  // expect an anonymous kXR_gpfile request
    byte    kXR_ExpLogin                = 0x03;  // expect a kXR_login request
    byte    kXR_ExpTPC                  = 0x04;  // expect a third-party copy

    /**
     *  _______________________________________________________________________
     *  PROTOCOL RESPONSE FLAGS
     *  _______________________________________________________________________
     */
    int     kXR_anongpf                 = 0x00800000; // Allows anonymous kXR_gpfile
    int     kXR_supgpf                  = 0x00400000; // Supports kXR_pgread & kXR_pgwrite
    int     kXR_suppgrw                 = 0x00200000; // Supports kXR_gpfile
    int     kXR_supposc                 = 0x00100000; // Supports kXR_posc open option
    int     kXR_haveTLS                 = 0x80000000; // Supports TLS connections
    int     kXR_gotoTLS                 = 0x40000000; // Connection will transition to TLS
    int     kXR_tlsAny                  = 0x1f000000; // to isolate tls requirement flags
    int     kXR_tlsData                 = 0x01000000; // All data requires a TLS connection
    int     kXR_tlsGPF                  = 0x02000000; // kXR_gpfile requires TLS
    int     kXR_tlsGPFA                 = 0x20000000; // anonymous kXR_gpfile requires TLS
    int     kXR_tlsLogin                = 0x04000000; // kXR_login requires a TLS connection
    int     kXR_tlsSess                 = 0x08000000; // Connection transition to TLS after login
    int     kXR_tlsTPC                  = 0x10000000; // TPC requests require a TLS connection

    /**
     *  _______________________________________________________________________
     *  QUERY REQUEST TYPES
     *  _______________________________________________________________________
     */
    int     kXR_QStats                  = 1;
    int     kXR_QPrep                   = 2;
    int     kXR_Qcksum                  = 3;
    int     kXR_Qxattr                  = 4;
    int     kXR_Qspace                  = 5;
    int     kXR_Qckscan                 = 6;
    int     kXR_Qconfig                 = 7;
    int     kXR_Qvisa                   = 8;
    int     kXR_Qopaque                 = 16;
    int     kXR_Qopaquf                 = 32;
    int     kXR_Qopaqug                 = 64;

    /**
     *  _______________________________________________________________________
     *  VERIFICATION TYPES
     *  _______________________________________________________________________
     */
    int     kXR_nocrc                   = 0;
    int     kXR_crc32                   = 1;

    /**
     *  _______________________________________________________________________
     *  LOGON TYPES
     *  _______________________________________________________________________
     */
    byte    kXR_useruser                = 0;
    byte    kXR_useradmin               = 1;

    /**
     *  _______________________________________________________________________
     *  PREPARE REQUEST OPTIONS
     *  _______________________________________________________________________
     */
    int     kXR_cancel                  = 0x01;
    int     kXR_notify                  = 0x02;
    int     kXR_noerrs                  = 0x04;
    int     kXR_stage                   = 0x08;
    int     kXR_wmode                   = 0x10;
    int     kXR_coloc                   = 0x20;
    int     kXR_fresh                   = 0x40;
    int     kXR_usetcp                  = 0x80;
    int     kXR_evict                   = 0x0001;  // optionsX: file no longer useful

    /**
     *  _______________________________________________________________________
     *  SERVER RESPONSE TYPES
     *  _______________________________________________________________________
     */
    int     kXR_ok                      = 0;
    int     kXR_oksofar                 = 4000;
    int     kXR_attn                    = 4001;
    int     kXR_authmore                = 4002;
    int     kXR_error                   = 4003;
    int     kXR_redirect                = 4004;
    int     kXR_wait                    = 4005;
    int     kXR_waitresp                = 4006;
    int     kXR_noResponsesYet          = 10000;

    /**
     *  _______________________________________________________________________
     *  SERVER ATTN CODES
     *  _______________________________________________________________________
     */
    int     kXR_asyncab                 = 5000;  // No longer supported
    int     kXR_asyncdi                 = 5001;  // No longer supported
    int     kXR_asyncms                 = 5002;
    int     kXR_asyncrd                 = 5003;  // No longer supported
    int     kXR_asyncwt                 = 5004;  // No longer supported
    int     kXR_asyncav                 = 5005;  // No longer supported
    int     kXR_asynunav                = 5006;  // No longer supported
    int     kXR_asyncgo                 = 5007;  // No longer supported
    int     kXR_asynresp                = 5008;
    int     kXR_asyninfo                = 5009;

    /**
     *  _______________________________________________________________________
     *  SERVER ERROR CODES (with corresponding POSIX errno)
     *  _______________________________________________________________________
     */
    int     kXR_ArgInvalid              = 3000;  // EINVAL
    int     kXR_ArgMissing              = 3001;  // EINVAL
    int     kXR_ArgTooLong              = 3002;  // ENAMETOOLONG
    int     kXR_FileLocked              = 3003;  // EDEADLK
    int     kXR_FileNotOpen             = 3004;  // EBADF
    int     kXR_FSError                 = 3005;  // ENODEV
    int     kXR_InvalidRequest          = 3006;  // EBADRQC
    int     kXR_IOError                 = 3007;  // EIO
    int     kXR_NoMemory                = 3008;  // ENOMEM
    int     kXR_NoSpace                 = 3009;  // ENOSPC
    int     kXR_NotAuthorized           = 3010;  // EACCES
    int     kXR_NotFound                = 3011;  // ENOENT
    int     kXR_ServerError             = 3012;  // EFAULT
    int     kXR_Unsupported             = 3013;  // ENOTSUP
    int     kXR_noserver                = 3014;  // EHOSTUNREACH
    int     kXR_NotFile                 = 3015;  // ENOTBLK
    int     kXR_isDirectory             = 3016;  // EISDIR
    int     kXR_Cancelled               = 3017;  // ECANCELED
    int     kXR_ItExists                = 3018;  // EEXIST
    int     kXR_ChkSumErr               = 3019;  // EDOM
    int     kXR_inProgress              = 3020;  // EINPROGRESS
    int     kXR_overQuota               = 3021;  // EDQUOT
    int     kXR_SigVerErr               = 3022;  // EILSEQ
    int     kXR_DecryptErr              = 3023;  // ERANGE
    int     kXR_Overloaded              = 3024;  // EUSERS
    int     kXR_fsReadOnly              = 3025;  // EROFS
    int     kXR_BadPayload              = 3026;  // EINVAL
    int     kXR_AttrNotFound            = 3027;  // ENOATTR
    int     kXR_TLSRequired             = 3028;  // EPROTOTYPE
    int     kXR_noReplicas              = 3029;  // EADDRNOTAVAIL
    int     kXR_AuthFailed              = 3030;  // EAUTH (preferable) or EBADE
    int     kXR_Impossible              = 3031;  // EIDRM
    int     kXR_Conflict                = 3032;  // ENOTTY
    int     kXR_noErrorYet              = 10000;

    @Deprecated // Kept for compatibility with plugins
    int     kXR_FileLockedr             = 3003;

    static String getServerError(int code) {
        switch (code) {
            case kXR_ArgInvalid: return "kXR_ArgInvalid";
            case kXR_ArgMissing: return "kXR_ArgMissing";
            case kXR_ArgTooLong: return "kXR_ArgTooLong";
            case kXR_FileLocked: return "kXR_FileLocked";
            case kXR_FileNotOpen: return "kXR_FileNotOpen";
            case kXR_FSError: return "kXR_FSError";
            case kXR_InvalidRequest: return "kXR_InvalidRequest";
            case kXR_IOError: return "kXR_IOError";
            case kXR_NoMemory: return "kXR_NoMemory";
            case kXR_NoSpace: return "kXR_NoSpace";
            case kXR_NotAuthorized: return "kXR_NotAuthorized";
            case kXR_NotFound: return "kXR_NotFound";
            case kXR_ServerError: return "kXR_ServerError";
            case kXR_Unsupported: return "kXR_Unsupported";
            case kXR_noserver: return "kXR_noserver";
            case kXR_NotFile: return "kXR_NotFile";
            case kXR_isDirectory: return "kXR_isDirectory";
            case kXR_Cancelled: return "kXR_Cancelled";
            case kXR_ItExists: return "kXR_ItExists";
            case kXR_ChkSumErr: return "kXR_ChkSumErr";
            case kXR_inProgress: return "kXR_inProgress";
            case kXR_overQuota: return "kXR_overQuota";
            case kXR_SigVerErr: return "kXR_SigVerErr";
            case kXR_DecryptErr: return "kXR_DecryptErr";
            case kXR_Overloaded: return "kXR_Overloaded";
            case kXR_fsReadOnly: return "kXR_fsReadOnly";
            case kXR_BadPayload: return "kXR_BadPayload";
            case kXR_AttrNotFound: return "kXR_AttrNotFound";
            case kXR_TLSRequired: return "kXR_TLSRequired";
            case kXR_noReplicas: return "kXR_noReplicas";
            case kXR_AuthFailed: return "kXR_AuthFailed";
            case kXR_Impossible: return "kXR_Impossible";
            case kXR_Conflict: return "kXR_Conflict";
            case kXR_noErrorYet: return "kXR_noErrorYet";
            default:
                return "unrecognized server error";
        }
    }
}