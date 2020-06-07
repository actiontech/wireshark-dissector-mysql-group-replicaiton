# wireshark-dissector-mysql-group-replicaiton

Wireshark dissector of MySQL Group Replication

# Notice

1. Support only xcom 1.2 protocol

# HOW-TO use

1. For Windows and Linux, follow the "HOW-TO compile" section. **PR on release app are welcome**
2. For Mac OSX:
	- Download the wireshark app under "Release" section
	- Install
	- Read the "Snapshot" section

# HOW-TO compile

1. git clone https://github.com/wireshark/wireshark.git
2. copy src/* to {wireshark_src}/plugins/epan/mysql_group_replication
3. copy CMakeListsCustom.txt to {wireshark_src}/CMakeListsCustom.txt
4. compile Wireshark, following the offical documents:
	* https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcBuildFirstTime.html
5. package Wireshark, foolowing the offical documents:
	* https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcBinary.html
6. the Wireshark package will be at {build_dir}/run/

# WHY provides Wireshark app instead of Plugin files

Plugin files should be provides by (OS version + Wireshark version), which is too complicated to handle.

An all-in-one Wireshark app is much easier for users.

Again, **PR on Windows/Linux/Mac OSX 10.14 are warmly welcome**
	
# Snapshot

![snapshot-1](https://github.com/actiontech/wireshark-dissector-mysql-group-replicaiton/blob/master/mgr_plugin_snapshot-1.png)

![snapshot](https://github.com/actiontech/wireshark-dissector-mysql-group-replicaiton/blob/master/mgr_plugin_snapshot.png)
