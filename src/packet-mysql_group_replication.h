#define MGR_DEFAULT_PORT (4406)
#define MGR_FRAME_HEADER_LEN (4+4+1+2+1)
#define BYTES_PER_XDR_UNIT (4)

static int proto_mgr = -1;
static int hf_protocol_version = -1;
static int hf_header_length = -1;
static int hf_header_xtype = -1;
static int hf_header_tag = -1;
static int hf_to_node_no = -1;
static int hf_from_node_no = -1;
static int hf_group_id = -1;
static int hf_max_synode_group_id = -1;
static int hf_max_synode_msgno = -1;
static int hf_max_synode_node = -1;
static int hf_start_type = -1;
static int hf_reply_to_cnt = -1;
static int hf_reply_to_node = -1;
static int hf_proposal_cnt = -1;
static int hf_proposal_node = -1;
static int hf_op = -1;
static int hf_synode_group_id = -1;
static int hf_synode_msgno = -1;
static int hf_synode_node = -1;
static int hf_msg_type = -1;
static int hf_receivers = -1;
static int hf_cli_err = -1;
static int hf_force_delivery = -1;
static int hf_refcnt = -1;
static int hf_delivered_msg_group_id = -1;
static int hf_delivered_msg_msgno = -1;
static int hf_delivered_msg_node = -1;
static gint ett_mgr = -1;
static gint ett_synode = -1;
static gint ett_max_synode = -1;
static gint ett_proposal = -1;
static gint ett_reply_to = -1;
static gint ett_app_data = -1;
static int hf_app_data_unique_id_group_id = -1;
static int hf_app_data_unique_id_msgno = -1;
static int hf_app_data_unique_id_node = -1;
static gint ett_app_data_unique_id = -1;
static int hf_app_data_group_id = -1;
static int hf_app_data_lsn = -1;
static int hf_app_data_app_key_group_id = -1;
static int hf_app_data_app_key_msgno = -1;
static int hf_app_data_app_key_node = -1;
static gint ett_app_data_app_key = -1;
static int hf_app_data_consensus = -1;
static int hf_app_data_expiry_time = -1;
static int hf_app_data_notused = -1;
static int hf_app_data_log_it = -1;
static int hf_app_data_chosen = -1;
static int hf_app_data_recover = -1;
static gint ett_app_data_body = -1;
static int hf_app_data_cargo_type = -1;
static int hf_app_data_nodes_address = -1;
static int hf_app_data_nodes_uuid = -1;
static int hf_app_data_nodes_min_proto = -1;
static int hf_app_data_nodes_max_proto = -1;
static gint ett_app_data_nodes = -1;
static int hf_app_data_rep_vers_group_id = -1;
static int hf_app_data_rep_vers_msgno = -1;
static int hf_app_data_rep_vers_node = -1;
static gint ett_app_data_rep_vers = -1;
static int hf_app_data_rep_msg_list_group_id = -1;
static int hf_app_data_rep_msg_list_msgno = -1;
static int hf_app_data_rep_msg_list_node = -1;
static gint ett_app_data_rep_msg_list = -1;
static int hf_app_data_rep_uncommitted_list_active = -1;
static int hf_app_data_rep_uncommitted_list_group_id = -1;
static int hf_app_data_rep_uncommitted_list_msgno = -1;
static int hf_app_data_rep_uncommitted_list_node = -1;
static gint ett_app_data_rep_uncommitted_list = -1;
static int hf_app_data_data = -1;
static gint ett_app_data_trans_data_tid = -1;
static int hf_app_data_trans_data_tid_cfg_group_id = -1;
static int hf_app_data_trans_data_tid_cfg_msgno = -1;
static int hf_app_data_trans_data_tid_cfg_node = -1;
static int hf_app_data_trans_data_tid_pc = -1;
static int hf_app_data_trans_data_pc = -1;
static int hf_app_data_trans_data_cluster_name = -1;
static int hf_app_data_trans_data_errmsg_nodeid = -1;
static int hf_app_data_trans_data_errmsg_code = -1;
static int hf_app_data_trans_data_errmsg_message = -1;
static int hf_app_data_present = -1;
static int hf_app_data_cache_limit = -1;
static int hf_app_data_has_next = -1;
static gint ett_app_data_next = -1;
static gint ett_snap = -1;
static int hf_snap_vers_group_id = -1;
static int hf_snap_vers_msgno = -1;
static int hf_snap_vers_node = -1;
static gint ett_snap_vers = -1;
static gint ett_snap_snap = -1;
static int hf_snap_u_list_uncommitted_list_active = -1;
static int hf_snap_u_list_uncommitted_list_group_id = -1;
static int hf_snap_u_list_uncommitted_list_msgno = -1;
static int hf_snap_u_list_uncommitted_list_node = -1;
static gint ett_snap_u_list_uncommitted_list = -1;
static gint ett_gcs_snap = -1;
static int hf_gcs_snap_log_start_group_id = -1;
static int hf_gcs_snap_log_start_msgno = -1;
static int hf_gcs_snap_log_start_node = -1;
static gint ett_gcs_snap_log_start = -1;
static int hf_gcs_snap_configs_start_group_id = -1;
static int hf_gcs_snap_configs_start_msgno = -1;
static int hf_gcs_snap_configs_start_node = -1;
static gint ett_gcs_snap_configs_start = -1;
static int hf_gcs_snap_configs_boot_key_group_id = -1;
static int hf_gcs_snap_configs_boot_key_msgno = -1;
static int hf_gcs_snap_configs_boot_key_node = -1;
static gint ett_gcs_snap_configs_boot_key = -1;
static gint ett_gcs_snap_configs = -1;
static int hf_gcs_snap_configs_nodes_address = -1;
static int hf_gcs_snap_configs_nodes_uuid = -1;
static int hf_gcs_snap_configs_nodes_min_proto = -1;
static int hf_gcs_snap_configs_nodes_max_proto = -1;
static gint ett_gcs_snap_configs_nodes = -1;
static int hf_gcs_snap_app_snap = -1;


static const value_string header_xtype_names[] = {
    { 0, "Normal message" },
    { 1, "Negotiate protocol version" },
    { 2, "Protocol version reply" }
};

static const value_string header_tag_names[] = {
    { 313, "TAG_START" }
};

static const value_string node_no_names[] = {
    { (~((guint32)0)), "VOID_NODE_NO" },
    { 0, NULL }
};

static const value_string start_type_names[] = {
    { 0, "IDLE" },
    { 1, "BOOT" },
    { 2, "RECOVER" }
};

static const value_string op_names[] = {
    {0, "client_msg"},
	{1, "initial_op"},
	{2, "prepare_op"},
	{3, "ack_prepare_op"},
	{4, "ack_prepare_empty_op"},
	{5, "accept_op"},
	{6, "ack_accept_op"},
	{7, "learn_op"},
	{8, "recover_learn_op"},
	{9, "multi_prepare_op"},
	{10, "multi_ack_prepare_empty_op"},
	{11, "multi_accept_op"},
	{12, "multi_ack_accept_op"},
	{13, "multi_learn_op"},
	{14, "skip_op"},
	{15, "i_am_alive_op"},
	{16, "are_you_alive_op"},
	{17, "need_boot_op"},
	{18, "snapshot_op"},
	{19, "die_op"},
	{20, "read_op"},
	{21, "gcs_snapshot_op"},
	{22, "xcom_client_reply"},
	{23, "tiny_learn_op"}
};

static const value_string pax_msg_type_names[] = {
    { 0, "normal" },
    { 1, "no_op" },
    { 2, "multi_no_op" }
};

static const value_string client_reply_code_names[] = {
    { 0, "REQUEST_OK" },
    { 1, "REQUEST_FAIL" },
    { 2, "REQUEST_RETRY" }
};

static const value_string cons_type_names[] = {
    { 0, "cons_majority" },
    { 1, "cons_all" },
    { 2, "cons_none" }
};

static const value_string recover_action_names[] = {
    { 0, "rec_block" },
    { 1, "rec_delay" },
    { 2, "rec_send" }
};

static const value_string cargo_type_names[] = {
    {0, "unified_boot_type"},
    {1, "xcom_boot_type"},
    {2, "xcom_set_group"},
    {3, "xcom_recover"},
    {4, "app_type"},
    {5, "query_type"},
    {6, "query_next_log"},
    {7, "exit_type"},
    {8, "reset_type"},
    {9, "begin_trans"},
    {10, "prepared_trans"},
    {11, "abort_trans"},
    {12, "view_msg"},
    {13, "remove_reset_type"},
    {14, "add_node_type"},
    {15, "remove_node_type"},
    {16, "enable_arbitrator"},
    {17, "disable_arbitrator"},
    {18, "force_config_type"},
    {19, "x_terminate_and_exit"},
    {20, "set_cache_limit"}
};

//ett = epan tree type  
static gint *etts[] = {
    &ett_mgr,
    &ett_synode,
    &ett_max_synode,
    &ett_proposal,
    &ett_reply_to,
    &ett_app_data,
    &ett_app_data_unique_id,
    &ett_app_data_app_key,
    &ett_app_data_body,
    &ett_app_data_nodes,
    &ett_app_data_rep_vers,
    &ett_app_data_rep_msg_list,
    &ett_app_data_rep_uncommitted_list,
    &ett_app_data_trans_data_tid,
    &ett_app_data_next,
    &ett_snap,
    &ett_snap_vers,
    &ett_snap_snap,
    &ett_snap_u_list_uncommitted_list,
    &ett_gcs_snap,
    &ett_gcs_snap_log_start,
    &ett_gcs_snap_configs,
    &ett_gcs_snap_configs_start,
    &ett_gcs_snap_configs_boot_key,
    &ett_gcs_snap_configs_nodes
};


static hf_register_info header_infos[] = {
    { &hf_protocol_version,
        { "protocol_version", "mgr.header.protocol_version",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_header_length,
        { "length", "mgr.header.length",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_header_xtype,
        { "xtype", "mgr.header.xtype",
        FT_UINT8, BASE_DEC,
        VALS(header_xtype_names), 0x0,
        NULL, HFILL }
    },
    { &hf_header_tag,
        { "tag", "mgr.header.tag",
        FT_UINT16, BASE_DEC,
        VALS(header_tag_names), 0x0,
        NULL, HFILL }
    },
    { &hf_to_node_no,
        { "to_node_no", "mgr.to_node_no",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_from_node_no,
        { "from_node_no", "mgr.from_node_no",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_group_id,
        { "group_id", "mgr.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_max_synode_group_id,
        { "max_synode.group_id", "mgr.max_synode.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_max_synode_msgno,
        { "max_synode.msgno", "mgr.max_synode.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_max_synode_node,
        { "max_synode.node", "mgr.max_synode.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_start_type,
        { "start_type", "mgr.start_type",
        FT_UINT32, BASE_DEC,
        VALS(start_type_names), 0x0,
        NULL, HFILL }
    },
    { &hf_reply_to_cnt,
        { "reply_to.cnt", "mgr.reply_to.cnt",
        FT_INT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_reply_to_node,
        { "reply_to.node", "mgr.reply_to.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_proposal_cnt,
        { "proposal.cnt", "mgr.proposal.cnt",
        FT_INT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_proposal_node,
        { "proposal.node", "mgr.proposal.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_op,
        { "op", "mgr.op",
        FT_UINT32, BASE_DEC,
        VALS(op_names), 0x0,
        NULL, HFILL }
    },
    { &hf_synode_group_id,
        { "synode.group_id", "mgr.synode.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_synode_msgno,
        { "synode.msgno", "mgr.synode.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_synode_node,
        { "synode.node", "mgr.synode.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_msg_type,
        { "msg_type", "mgr.msg_type",
        FT_UINT32, BASE_DEC,
        VALS(pax_msg_type_names), 0x0,
        NULL, HFILL }
    },
    { &hf_receivers,
        { "receivers", "mgr.receivers",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_cli_err,
        { "cli_err", "mgr.cli_err",
        FT_UINT32, BASE_DEC,
        client_reply_code_names, 0x0,
        NULL, HFILL }
    },
    { &hf_force_delivery,
        { "force_delivery", "mgr.force_delivery",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_refcnt,
        { "refcnt", "mgr.refcnt",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_delivered_msg_group_id,
        { "delivered_msg.group_id", "mgr.delivered_msg.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_delivered_msg_msgno,
        { "delivered_msg.msgno", "mgr.delivered_msg.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_delivered_msg_node,
        { "delivered_msg.node", "mgr.delivered_msg.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_unique_id_group_id,
        { "app_data.unique_id.group_id", "mgr.app_data.unique_id.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_unique_id_msgno,
        { "app_data.unique_id.msgno", "mgr.app_data.unique_id.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_unique_id_node,
        { "app_data.unique_id.node", "mgr.app_data.unique_id.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_group_id,
        { "app_data.group_id", "mgr.app_data.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_lsn,
        { "app_data.lsn", "mgr.app_data.lsn",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_app_key_group_id,
        { "app_data.app_key.group_id", "mgr.app_data.app_key.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_app_key_msgno,
        { "app_data.app_key.msgno", "mgr.app_data.app_key.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_app_key_node,
        { "app_data.app_key.node", "mgr.app_data.app_key.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_consensus,
        { "app_data.consensus", "mgr.app_data.consensus",
        FT_UINT32, BASE_DEC,
        VALS(cons_type_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_expiry_time,
        { "app_data.expiry_time", "mgr.app_data.expiry_time",
        FT_DOUBLE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_notused,
        { "app_data.notused", "mgr.app_data.notused",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_log_it,
        { "app_data.log_it", "mgr.app_data.log_it",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_chosen,
        { "app_data.chosen", "mgr.app_data.chosen",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_recover,
        { "app_data.recover", "mgr.app_data.recover",
        FT_UINT32, BASE_DEC,
        VALS(recover_action_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_cargo_type,
        { "app_data.body.cargo_type", "mgr.app_data.body.cargo_type",
        FT_UINT32, BASE_DEC,
        VALS(cargo_type_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_nodes_address,
        { "app_data.body.nodes.address", "mgr.app_data.body.nodes.address",
        FT_UINT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_nodes_uuid,
        { "app_data.body.nodes.uuid", "mgr.app_data.body.nodes.uuid",
        FT_UINT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_nodes_min_proto,
        { "app_data.body.nodes.min_proto", "mgr.app_data.body.nodes.min_proto",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_nodes_max_proto,
        { "app_data.body.nodes.max_proto", "mgr.app_data.body.nodes.max_proto",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_vers_group_id,
        { "app_data.body.rep.group_id", "mgr.app_data.body.rep.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_vers_msgno,
        { "app_data.body.rep.msgno", "mgr.app_data.body.rep.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_vers_node,
        { "app_data.body.rep.node", "mgr.app_data.body.rep.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_msg_list_group_id,
        { "app_data.body.msg_list.group_id", "mgr.app_data.body.msg_list.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_msg_list_msgno,
        { "app_data.body.msg_list.msgno", "mgr.app_data.body.msg_list.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_msg_list_node,
        { "app_data.body.msg_list.node", "mgr.app_data.body.msg_list.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_uncommitted_list_active,
        { "app_data.body.uncommitted_list.active", "mgr.app_data.body.uncommitted_list.active",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_uncommitted_list_group_id,
        { "app_data.body.uncommitted_list.group_id", "mgr.app_data.body.uncommitted_list.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_uncommitted_list_msgno,
        { "app_data.body.uncommitted_list.msgno", "mgr.app_data.body.uncommitted_list.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_rep_uncommitted_list_node,
        { "app_data.body.uncommitted_list.node", "mgr.app_data.body.uncommitted_list.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_data,
        { "app_data.body.data", "mgr.app_data.body.data",
        FT_UINT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_trans_data_tid_cfg_group_id,
        { "app_data.body.trans_data.tid.cfg.group_id", "mgr.app_data.body.trans_data.tid.cfg.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_trans_data_tid_cfg_msgno,
        { "app_data.body.trans_data.tid.cfg.msgno", "mgr.app_data.body.trans_data.tid.cfg.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_trans_data_tid_cfg_node,
        { "app_data.body.trans_data.tid.cfg.node", "mgr.app_data.body.trans_data.tid.cfg.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_trans_data_tid_pc,
        { "app_data.body.trans_data.tid.pc", "mgr.app_data.body.trans_data.tid.pc",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_trans_data_pc,
        { "app_data.body.trans_data.pc", "mgr.app_data.body.trans_data.pc",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_trans_data_cluster_name,
        { "app_data.body.trans_data.cluster_name", "mgr.app_data.body.trans_data.cluster_name",
        FT_UINT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_trans_data_errmsg_nodeid,
        { "app_data.body.trans_data.errmsg.nodeid", "mgr.app_data.body.trans_data.errmsg.nodeid",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_trans_data_errmsg_code,
        { "app_data.body.trans_data.errmsg.code", "mgr.app_data.body.trans_data.errmsg.code",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_trans_data_errmsg_message,
        { "app_data.body.trans_data.errmsg.message", "mgr.app_data.body.trans_data.errmsg.message",
        FT_UINT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_present,
        { "app_data.body.present", "mgr.app_data.body.present",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_cache_limit,
        { "app_data.body.cache_limit", "mgr.app_data.body.cache_limit",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_app_data_has_next,
        { "app_data.has_next", "mgr.app_data.has_next",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_snap_u_list_uncommitted_list_active,
        { "snap.u_list.uncommitted_list.active", "mgr.snap.u_list.uncommitted_list.active",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_snap_u_list_uncommitted_list_group_id,
        { "snap.u_list.uncommitted_list.group_id", "mgr.snap.u_list.uncommitted_list.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_snap_u_list_uncommitted_list_msgno,
        { "snap.u_list.uncommitted_list.msgno", "mgr.snap.u_list.uncommitted_list.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_snap_u_list_uncommitted_list_node,
        { "snap.u_list.uncommitted_list.node", "mgr.snap.u_list.uncommitted_list.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_log_start_group_id,
        { "gcs_snap.log_start.group_id", "mgr.gcs_snap.log_start.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_log_start_msgno,
        { "gcs_snap.log_start.msgno", "mgr.gcs_snap.log_start.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_log_start_node,
        { "gcs_snap.log_start.node", "mgr.gcs_snap.log_start.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_start_group_id,
        { "gcs_snap.configs.start.group_id", "mgr.gcs_snap.configs.start.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_start_msgno,
        { "gcs_snap.configs.start.msgno", "mgr.gcs_snap.configs.start.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_start_node,
        { "gcs_snap.configs.start.node", "mgr.gcs_snap.configs.start.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_boot_key_group_id,
        { "gcs_snap.configs.boot_key.group_id", "mgr.gcs_snap.configs.boot_key.group_id",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_boot_key_msgno,
        { "gcs_snap.configs.boot_key.msgno", "mgr.gcs_snap.configs.boot_key.msgno",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_boot_key_node,
        { "gcs_snap.configs.boot_key.node", "mgr.gcs_snap.configs.boot_key.node",
        FT_UINT32, BASE_DEC,
        VALS(node_no_names), 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_nodes_address,
        { "gcs_snap.configs.nodes.address", "mgr.gcs_snap.configs.nodes.address",
        FT_UINT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_nodes_uuid,
        { "gcs_snap.configs.nodes.uuid", "mgr.gcs_snap.configs.nodes.uuid",
        FT_UINT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_nodes_min_proto,
        { "gcs_snap.configs.nodes.min_proto", "mgr.gcs_snap.configs.nodes.min_proto",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_configs_nodes_max_proto,
        { "gcs_snap.configs.nodes.max_proto", "mgr.gcs_snap.configs.nodes.max_proto",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gcs_snap_app_snap,
        { "gcs_snap.app_snap", "mgr.gcs_snap.app_snap",
        FT_UINT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    }
};