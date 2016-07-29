# SpanFS
#Introduction
SpanFS is a Scalable File System on Fast Storage Devices, which aims to provide scalable I/O performance on many-core platform incorporating fast storage technologies.
As demonstrated in our paper, the scalability bottlenecks of exitsting file systems are mainly caused by two factors: the use of shared in-memory data structures and the serialization of internl I/O activities on fast storage devices.

In order to address the scalability bottlenecks, we proposed SpanFS, which builds a file system with multiple independent micro-filesystem services called domains.
Then, SpanFS distributes all files and directories among the domains and provides a global file system view on top of the domains.
Each domian adopts traditional journaling mechanism to ensure its local consistency.
We build the logical connection (bidirectional index) among the domains beyond the underlying distributed journaling, then propose a set of techniques to maintain global consistency based on the connection.
SpanFS is implemented based on Ext4 in Linux 3.18.0.

For more details, please refer to our paper:
[SpanFS: A Scalable File System on Fast Storage Devices ](https://www.usenix.org/system/files/conference/atc15/atc15-paper-kang.pdf)<bf />







