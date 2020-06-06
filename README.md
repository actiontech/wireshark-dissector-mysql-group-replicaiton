# wireshark-dissector-mysql-group-replicaiton

Wireshark dissector of MySQL Group Replication

# Notice

1. Support only xcom 1.2 protocol

# HOW-TO use

1. For Windows and Linux, follow the "HOW-TO compile" section
2. For Mac OSX:
	- download the plugin under "Release" section
	- copy the plugin to the setup directory, for example: `/Application/Wireshark.app/Contents/PlugIns/wireshark/3-3/epan/mysql_group_replication.so`

# HOW-TO compile

1. git clone https://github.com/wireshark/wireshark.git
2. copy src/* to wireshark/plugins/epan/mysql_group_replication
3. compile Wireshark, following the offical documents:
	* https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcBuildFirstTime.html
4. the plugin dist is at {build_dir}/run/... 
	- Mac OS X: `{build_dir}/run/Wireshark.app/Contents/PlugIns/wireshark/3-3/epan/mysql_group_replication.so`
5. copy the plugin to your setup directory
	- Mac OS X: `/Application/Wireshark.app/Contents/PlugIns/wireshark/3-3/epan/mysql_group_replication.so`
	
# Snapshot

![snapshot](https://github.com/actiontech/wireshark-dissector-mysql-group-replicaiton/blob/master/mgr_plugin_snapshot.png)
