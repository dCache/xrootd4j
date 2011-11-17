xrootd4j
========

Implementation of the xrootd data access protocol in Java. The project
provides a library for integration and a standalone xrootd data
server.

About the library
-----------------

[xrootd] is the native data access protocol of the [ROOT] data
analysis framework. The official implementation of the protocol is
provided by SLAC National Accelerator Laboratory.

[dCache] is a distributed storage system frequently used in the
[Worldwide LHC Computing Grid][WLCG], high energy physics, photon
sciences, and a couple of other communities.

This project provides our implementation of the xrootd data access
protocol in Java. The library is used to implement the xrootd support
in dCache.

A standalone data server is provided. The primary purpose of the
standalone data server is for testing, both interoperability testing
and as a platform to test plugins without having to install dCache.

Compilation
-----------

To compile the project simply execute:

    mvn package


Installing the library
----------------------

To install the core library (xrootd4j) into your local maven
repository run:

    mvn -am -pl xrootd4j install


Using the library
-----------------

Add the following Maven dependency to your project:

    <dependency>
        <groupId>org.dcache</groupId>
        <artifactId>xrootd4j</artifactId>
        <version>1.0-SNAPSHOT</version>
    </dependency>

Starting the standalone server
------------------------------

The standalone server may be executed as follows:

    java -Dlog=debug  -jar xrootd-standalone/target/xrootd-standalone-1.0-SNAPSHOT-jar-with-dependencies.jar 


Please adjust the log level as needed. Add the -h option at the end of
the command to get a brief synopsis of available options.

Authors
-------

The code was originally written by Martin Radicke and sponsored by
[DESY]. It has since been maintained by Gerd Behrmann and sponsored by
[NDGF].

[ALICE]:  http://aliweb.cern.ch/
[dCache]: http://www.dcache.org/
[xrootd]: http://xrootd.slac.stanford.edu/
[WLCG]: http://lcg.web.cern.ch/lcg/
[NDGF]: http://www.ndgf.org/
[DESY]: http://www.desy.de/
