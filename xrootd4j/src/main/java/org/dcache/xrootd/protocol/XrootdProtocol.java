/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.protocol;

public interface XrootdProtocol {

    /*  current supported protocol version: 2.89
     * Xrootd expects the protocol information binary encoded in an int32
     */
    public static final int  PROTOCOL_VERSION = 0x289;
    public static final byte PROTOCOL_VERSION_MAJOR =
        (byte) ((PROTOCOL_VERSION & 0xFF00) >> 8);
    public static final byte PROTOCOL_VERSION_MINOR =
        (byte) (PROTOCOL_VERSION & 0x00FF);

    public static final byte      CLIENT_REQUEST_LEN = 24;
    public static final byte    CLIENT_HANDSHAKE_LEN = 20;
    public static final byte     SERVER_RESPONSE_LEN = 8;
    public static final int            LOAD_BALANCER = 0;
    public static final int              DATA_SERVER = 1;

    public static final byte[] HANDSHAKE_REQUEST = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 7, (byte) 220};
    public static final byte[] HANDSHAKE_RESPONSE_LOADBALANCER = {0, 0, 0, 0, 0, 0, 0, 8, 0, 0, PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR , 0, 0, 0, LOAD_BALANCER};
    public static final byte[] HANDSHAKE_RESPONSE_DATASERVER = {0, 0, 0, 0, 0, 0, 0, 8, 0, 0, PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR, 0, 0, 0, DATA_SERVER};

    // server response codes
    public static final int   kXR_ok       = 0;
    public static final int   kXR_oksofar  = 4000;
    public static final int   kXR_authmore = 4002;
    public static final int   kXR_error    = 4003;
    public static final int   kXR_redirect = 4004;
    public static final int   kXR_wait     = 4005;
    public static final int   kXR_waitresp = 4006;
    public static final int   kXR_noResponseYet = 10000;

    // server error codes
    public static final int   kXR_ArgInvalid     = 3000;
    public static final int   kXR_ArgMissing     = 3001;
    public static final int   kXR_ArgTooLong     = 3002;
    public static final int   kXR_FileLocked     = 3003;
    public static final int   kXR_FileNotOpen    = 3004;
    public static final int   kXR_FSError        = 3005;
    public static final int   kXR_InvalidRequest = 3006;
    public static final int   kXR_IOError        = 3007;
    public static final int   kXR_NoMemory       = 3008;
    public static final int   kXR_NoSpace        = 3009;
    public static final int   kXR_NotAuthorized  = 3010;
    public static final int   kXR_NotFound       = 3011;
    public static final int   kXR_ServerError    = 3012;
    public static final int   kXR_Unsupported    = 3013;
    public static final int   kXR_noserver       = 3014;
    public static final int   kXR_NotFile        = 3015;
    public static final int   kXR_isDirectory    = 3016;
    public static final int   kXR_Cancelled      = 3017;
    public static final int   kXR_ChkLenErr      = 3018;
    public static final int   kXR_ChkSumErr      = 3019;
    public static final int   kXR_inProgress     = 3020;
    public static final int   kXR_noErrorYet     = 10000;

    // client's request types
    public static final int   kXR_handshake = 0;
    public static final int   kXR_auth      = 3000;
    public static final int   kXR_query     = 3001;
    public static final int   kXR_chmod     = 3002;
    public static final int   kXR_close     = 3003;
    public static final int   kXR_dirlist   = 3004;
    public static final int   kXR_getfile   = 3005;
    public static final int   kXR_protocol  = 3006;
    public static final int   kXR_login     = 3007;
    public static final int   kXR_mkdir     = 3008;
    public static final int   kXR_mv        = 3009;
    public static final int   kXR_open      = 3010;
    public static final int   kXR_ping      = 3011;
    public static final int   kXR_putfile   = 3012;
    public static final int   kXR_read      = 3013;
    public static final int   kXR_rm        = 3014;
    public static final int   kXR_rmdir     = 3015;
    public static final int   kXR_sync      = 3016;
    public static final int   kXR_stat      = 3017;
    public static final int   kXR_set       = 3018;
    public static final int   kXR_write     = 3019;
    public static final int   kXR_admin     = 3020;
    public static final int   kXR_prepare   = 3021;
    public static final int   kXR_statx     = 3022;
    public static final int   kXR_endsess   = 3023;
    public static final int   kXR_bind      = 3024;
    public static final int   kXR_readv     = 3025;
    public static final int   kXR_verifyw   = 3026;
    public static final int   kXR_locate    = 3027;
    public static final int   kXR_truncate  = 3028;

    // open mode for remote files
    public static final short kXR_ur = 0x100;
    public static final short kXR_uw = 0x080;
    public static final short kXR_ux = 0x040;
    public static final short kXR_gr = 0x020;
    public static final short kXR_gw = 0x010;
    public static final short kXR_gx = 0x008;
    public static final short kXR_or = 0x004;
    public static final short kXR_ow = 0x002;
    public static final short kXR_ox = 0x001;

    // open request options
    public static final short kXR_compress  = 1;
    public static final short kXR_delete    = 2;
    public static final short kXR_force     = 4;
    public static final short kXR_new       = 8;
    public static final short kXR_open_read = 16;
    public static final short kXR_open_updt = 32;
    public static final short kXR_async     = 64;
    public static final short kXR_refresh       = 128;
    public static final short kXR_mkpath        = 256;
    public static final short kXR_open_apnd     = 512;
    public static final short kXR_retstat       = 1024;
    public static final short kXR_replica       = 2048;
    public static final short kXR_posc          = 4096;
    public static final short kXR_nowait        = 8192;
    public static final short kXR_seqio         = 16384;

    // stat response flags
    public static final int kXR_file    =  0;
    public static final int kXR_xset    =  1;
    public static final int kXR_isDir   =  2;
    public static final int kXR_other   =  4;
    public static final int kXR_offline =  8;
    public static final int kXR_readable= 16;
    public static final int kXR_writable= 32;
    public static final int kXR_poscpend= 64;


    // attn response codes
    public static final int kXR_asyncab         = 5000;
    public static final int kXR_asyncdi         = 5001;
    public static final int kXR_asyncms         = 5002;
    public static final int kXR_asyncrd         = 5003;
    public static final int kXR_asyncwt         = 5004;
    public static final int kXR_asyncav         = 5005;
    public static final int kXR_asynunav        = 5006;
    public static final int kXR_asyncgo         = 5007;
    public static final int kXR_asynresp        = 5008;

    // prepare request options
    public static final int kXR_cancel = 1;
    public static final int kXR_notify = 2;
    public static final int kXR_noerrs = 4;
    public static final int kXR_stage  = 8;
    public static final int kXR_wmode  = 16;
    public static final int kXR_coloc  = 32;
    public static final int kXR_fresh  = 64;

    // verification options
    public static final int kXR_nocrc = 0;
    public static final int kXR_crc32 = 1;

    // query types
    public static final int kXR_QStats = 1;
    public static final int kXR_QPrep  = 2;
    public static final int kXR_Qcksum = 3;
    public static final int kXR_Qxattr = 4;
    public static final int kXR_Qspace = 5;
    public static final int kXR_Qckscan= 6;
    public static final int kXR_Qconfig= 7;
    public static final int kXR_Qvisa  = 8;
    public static final int kXR_Qopaque=16;
    public static final int kXR_Qopaquf=32;

    // dirlist options
    public static final int kXR_online = 1;

    // mkdir options
    public static final int kXR_mknone    = 0;
    public static final int kXR_mkdirpath = 1;

    // login cap version
    public static final int kXR_lcvnone   = 0;
    public static final int kXR_vermask   = 63;
    public static final int kXR_asyncap   = 128;

    // login version
    public static final int kXR_ver000 = 0; // old clients predating history
    public static final int kXR_ver001 = 1; // generally implemented 2005 prot.
    public static final int kXR_ver002 = 2; // recognizes asyncresp

    // stat options
    public static final int kXR_vfs = 1;

    // logon types
    public static final byte kXR_useruser = 0;
    public static final byte kXR_useradmin = 1;

    public static final int DEFAULT_PORT = 1094;

    public static final int SESSION_ID_SIZE = 16;

    /* All possible access permissions when using xrootd authZ
     * these are the possbile permission level, one file can have only one type
     * (no combinations) the granted rights increase in the order of appereance
     * (e.g. delete includes write, which includes read and write-once)
     */
    public static enum FilePerm {
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

    /* passing information from the door to the pool */
    public static final String UUID_PREFIX = "org.dcache.uuid";
}
