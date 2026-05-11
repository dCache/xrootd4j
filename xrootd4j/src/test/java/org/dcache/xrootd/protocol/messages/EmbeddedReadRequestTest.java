package org.dcache.xrootd.protocol.messages;

import static org.junit.Assert.*;

import java.util.Arrays;
import org.dcache.xrootd.protocol.messages.GenericReadRequestMessage.EmbeddedReadRequest;
import org.junit.Test;

public class EmbeddedReadRequestTest {

    @Test
    public void testCompareTo() {

        EmbeddedReadRequest[] readvSorted = new EmbeddedReadRequest[]{
              new EmbeddedReadRequest(1, 10, 10),
              new EmbeddedReadRequest(1, 10, 40),

              new EmbeddedReadRequest(2, 10, 0),
              new EmbeddedReadRequest(2, 10, 10),
              new EmbeddedReadRequest(2, 10, 20),
              new EmbeddedReadRequest(2, 10, 40),
              new EmbeddedReadRequest(2, 10, 80),
              new EmbeddedReadRequest(2, 10, 100),
        };

        EmbeddedReadRequest[] readv = new EmbeddedReadRequest[]{
              new EmbeddedReadRequest(2, 10, 100),
              new EmbeddedReadRequest(1, 10, 10),
              new EmbeddedReadRequest(1, 10, 40),

              new EmbeddedReadRequest(2, 10, 0),
              new EmbeddedReadRequest(2, 10, 40),
              new EmbeddedReadRequest(2, 10, 10),
              new EmbeddedReadRequest(2, 10, 20),
              new EmbeddedReadRequest(2, 10, 80),
        };

        Arrays.sort(readv);
        assertArrayEquals("unexpected order of read requests (invalid sorting)", readvSorted, readv);

    }
}