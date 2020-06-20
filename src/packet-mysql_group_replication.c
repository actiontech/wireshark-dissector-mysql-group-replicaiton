/* packet-mysql_group_replication.c
 *
 * Updated routines for Gryphon protocol packet dissection
 * By Yan Huang <tac.nil@outlook.com>
 * Copyright 2020 Yan Huang
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include "config.h"
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include "packet-mysql_group_replication.h"

static int
decode_synode_no(tvbuff_t *tvb, int offset, proto_tree *pt, 
    int _hf_synode_group_id, int _hf_synode_msgno, int _hf_synode_node)
{
    proto_tree_add_item(pt, _hf_synode_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(pt, _hf_synode_msgno, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(pt, _hf_synode_node, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
decode_synode_no_list(tvbuff_t *tvb, int offset, proto_tree *pt, 
    gint32 _ett,
    int _hf_synode_group_id, int _hf_synode_msgno, int _hf_synode_node)
{
    proto_tree *sub_tree;
    gint32 len = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;

    for (int i = 0; i < len; ++i)
    {
        sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 16, _ett, NULL, "rep_vers");
        offset = decode_synode_no(tvb, offset, sub_tree, 
            _hf_synode_group_id, _hf_synode_msgno, _hf_synode_node);
    }

    return offset;
}

static int
decode_ballot(tvbuff_t *tvb, int offset, proto_tree *pt, 
    int _hf_cnt, int _hf_node)
{
    proto_tree_add_item(pt, _hf_cnt, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(pt, _hf_node, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int decode_string(tvbuff_t *tvb, int offset, proto_tree *pt, int _hf)
{
    //_hf should be defined as FT_UINT_STRING
    gint32 len;
    proto_tree_add_item_ret_length(pt, _hf, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
    offset += len;
    if (len % BYTES_PER_XDR_UNIT > 0)
    {
        offset += BYTES_PER_XDR_UNIT - len % BYTES_PER_XDR_UNIT;
    }
    return offset;
}

static int decode_bytes(tvbuff_t *tvb, int offset, proto_tree *pt, int _hf)
{
    //_hf should be defined as FT_UINT_BYTES
    gint32 len;
    proto_tree_add_item_ret_length(pt, _hf, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
    offset += len;
    if (len % BYTES_PER_XDR_UNIT > 0)
    {
        offset += BYTES_PER_XDR_UNIT - len % BYTES_PER_XDR_UNIT;
    }
    return offset;
}

static int
decode_node_list_1_1(tvbuff_t *tvb, int offset, proto_tree *pt,
    int _hf_nodes_address,
    int _hf_nodes_uuid,
    int _hf_nodes_min_proto,
    int _hf_nodes_max_proto)
{
    gint32 count = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;

    for (int i = 0; i < count; ++i)
    {
        offset = decode_string(tvb, offset, pt, _hf_nodes_address);

        offset = decode_bytes(tvb, offset, pt, _hf_nodes_uuid);

        proto_tree_add_item(pt, _hf_nodes_min_proto, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(pt, _hf_nodes_max_proto, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return offset;
}

static int
decode_uncommitted_list(tvbuff_t *tvb, int offset, proto_tree *pt,
    int _hf_active,
    gint _ett_uncommitted_list,
    int _hf_uncommitted_list_group_id,
    int _hf_uncommitted_list_msgno,
    int _hf_uncommitted_list_node
    )
{
    proto_tree_add_item(pt, _hf_active, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = decode_synode_no_list(tvb, offset, pt, _ett_uncommitted_list,
        _hf_uncommitted_list_group_id, _hf_uncommitted_list_msgno, _hf_uncommitted_list_node);

    return offset;
}

static int decode_gcs_plugin_msg_payload_item_type_and_length(tvbuff_t *tvb, int offset, guint32* type, guint64* length)
{
    if (type != NULL)
    {
        *type = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    }
    offset += 2;

    if (length != NULL) {
        *length = tvb_get_guint64(tvb, offset, ENC_LITTLE_ENDIAN);
    }
    offset += 8;

    return offset;
}

static int decode_gcs_plugin_msg_decode_payload_item(tvbuff_t *tvb, int offset, proto_tree *pt, int _hf)
{
    guint64 length;
    offset = decode_gcs_plugin_msg_payload_item_type_and_length(tvb, offset, NULL, &length);
    
    int length_int = (int)length; //FIXME
    proto_tree_add_item(pt, _hf, tvb, offset, length_int, ENC_LITTLE_ENDIAN);
    offset += length;

    return offset;
}

static int decode_plugin_gcs_message_header(tvbuff_t *tvb, int offset, guint16* cargo_type)
{
    //version
    offset += 4;

    //fixed_header_len
    offset += 2;

    //msg_len
    offset += 8;

    //cargo_type
    if (cargo_type != NULL) {
        *cargo_type = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    }
    offset += 2;

    return offset;
}

static int
decode_gcs_msg(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    uint len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;

    if (len % BYTES_PER_XDR_UNIT > 0)
    {
        len += (BYTES_PER_XDR_UNIT - len % BYTES_PER_XDR_UNIT);
    }
    int end_offset = offset + len;

    proto_tree *sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, len, ett_gcs_msg, NULL, "gcs_msg");
    proto_tree_add_item(sub_tree, hf_gcs_msg_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* int fixed_header_len = */ tvb_get_gint16(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* int msg_len = */ tvb_get_gint64(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 8;

    int dynamic_headers_len = tvb_get_gint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 4;

    guint32 cargo_type;
    proto_tree_add_item_ret_uint(sub_tree, hf_gcs_msg_cargo_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &cargo_type);
    offset += 2;

    if (dynamic_headers_len > 0)
    {
        //TODO
        proto_tree_add_uint(sub_tree, hf_TODO, tvb, offset, 0, 1);
        return end_offset;
    }

    if (cargo_type == 1 /* CT_INTERNAL_STATE_EXCHANGE */)
    {
        guint32 wire_header_len = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* int WIRE_PAYLOAD_LEN_SIZE = */ tvb_get_gint64(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 8;

        offset += wire_header_len;

        proto_tree_add_item(sub_tree, hf_xcom_member_state_fixed_view_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        proto_tree_add_item(sub_tree, hf_xcom_member_state_monotonic_view_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(sub_tree, hf_xcom_member_state_group_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(sub_tree, hf_xcom_member_state_msg_no, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        proto_tree_add_item(sub_tree, hf_xcom_member_state_node, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        //Gcs_message_data.header_len
        wire_header_len = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 4;

        //Gcs_message_data.payload_len
        offset += 8;

        offset += wire_header_len;

        guint16 plugin_gcs_cargo_type;
        offset = decode_plugin_gcs_message_header(tvb, offset, &plugin_gcs_cargo_type);
        proto_tree_add_uint(sub_tree, hf_xcom_member_state_payload_cargo_type, tvb, offset, 2, plugin_gcs_cargo_type);

        //Group_member_info_manager_message.number_of_members.payload.type/length
        offset = decode_gcs_plugin_msg_payload_item_type_and_length(tvb, offset, NULL, NULL);
        
        int member_count;
        proto_tree_add_item_ret_uint(sub_tree, hf_group_member_info_member_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &member_count);
        offset += 2;

        for (int i = 0; i < member_count; ++i)
        {
            offset = decode_plugin_gcs_message_header(tvb, offset, NULL);

            //Group_member_info_manager_message.members.payload.type/length
            offset = decode_gcs_plugin_msg_payload_item_type_and_length(tvb, offset, NULL, NULL);

            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_hostname);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_port);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_uuid);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_gcs_member_id);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_status);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_member_version);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_write_set_extraction_algorithm);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_executed_gtid_set);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_retrieved_gtid_set);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_gtid_assignment_block_size);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_role);
            offset = decode_gcs_plugin_msg_decode_payload_item(tvb, offset, sub_tree, hf_group_member_info_configuration_flags);

            while (offset + 10 /* WIRE_PAYLOAD_ITEM_HEADER_SIZE */ < end_offset)
            {
                int payload_type;
                offset = decode_gcs_plugin_msg_payload_item_type_and_length(tvb, offset, &payload_type, NULL);

                switch (payload_type) 
                {
                case 13 /* PIT_CONFLICT_DETECTION_ENABLE */:
                    proto_tree_add_item(sub_tree, hf_group_member_info_conflict_detection_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    break;
                case 14 /* PIT_MEMBER_WEIGHT */:
                    proto_tree_add_item(sub_tree, hf_group_member_info_member_weight, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    break;
                }
            }
        }
    }


    return end_offset;
}

static int
decode_app_data_body(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    guint32 cargo_type;
    proto_tree_add_item_ret_uint(pt, hf_app_data_cargo_type, tvb, offset, 4, ENC_BIG_ENDIAN, &cargo_type);
    offset += 4;

    proto_tree *sub_tree;
    gint32 saved_offset;
    gint32 len;

    switch (cargo_type) {
        case 0 /* unified_boot_type */:
        case 14 /* add_node_type */:
        case 15 /* remove_node_type */:
        case 18 /* force_config_type */:
        case 1 /* xcom_boot_type */:
        case 2 /* xcom_set_group */:
            saved_offset = offset;
            sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 0, ett_app_data_nodes, NULL, "nodes");
            offset = decode_node_list_1_1(tvb, offset, sub_tree,
                hf_app_data_nodes_address,
                hf_app_data_nodes_uuid,
                hf_app_data_nodes_min_proto,
                hf_app_data_nodes_max_proto);
            proto_item_set_len(sub_tree, offset - saved_offset);
            break;
        case 3 /* xcom_recover */:
            sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 16, ett_app_data_rep_vers, NULL, "rep_vers");
            offset = decode_synode_no(tvb, offset, sub_tree, 
                hf_app_data_rep_vers_group_id, hf_app_data_rep_vers_msgno, hf_app_data_rep_vers_node);

            offset = decode_synode_no_list(tvb, offset, pt, ett_app_data_rep_msg_list,
                hf_app_data_rep_msg_list_group_id, hf_app_data_rep_msg_list_msgno, hf_app_data_rep_msg_list_node);

            offset = decode_uncommitted_list(tvb, offset, pt, hf_app_data_rep_uncommitted_list_active,
                ett_app_data_rep_uncommitted_list,
                hf_app_data_rep_uncommitted_list_group_id, hf_app_data_rep_uncommitted_list_msgno, hf_app_data_rep_uncommitted_list_node);

            break;
        case 4 /* app_type */:
            offset = decode_gcs_msg(tvb, offset, pt);
            break;
        case 5 /* query_type */:
        case 6 /* query_next_log */:
        case 7 /* exit_type */:
        case 8 /* reset_type */:
        case 13 /* remove_reset_type */:
        case 9 /* begin_trans */:
            break;
        case 10 /* prepared_trans */:
        case 11 /* abort_trans */:
            sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 16, ett_app_data_trans_data_tid, NULL, "rep_vers");
            offset = decode_synode_no(tvb, offset, sub_tree, 
                hf_app_data_trans_data_tid_cfg_group_id, hf_app_data_trans_data_tid_cfg_msgno, hf_app_data_trans_data_tid_cfg_node);
            proto_tree_add_item(sub_tree, hf_app_data_trans_data_tid_pc, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(pt, hf_app_data_trans_data_pc, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            offset = decode_string(tvb, offset, pt, hf_app_data_trans_data_cluster_name);

            proto_tree_add_item(pt, hf_app_data_trans_data_errmsg_nodeid, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(pt, hf_app_data_trans_data_errmsg_code, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            offset = decode_string(tvb, offset, pt, hf_app_data_trans_data_errmsg_message);
            break;

        case 12 /* view_msg */:
            len = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
            offset += 4;
            for (int i = 0; i < len; ++i)
            {
                proto_tree_add_item(pt, hf_app_data_present, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            break;
        case 20 /* set_cache_limit */:
            proto_tree_add_item(pt, hf_app_data_present, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            break;
        default:
            break;
    }
    return offset;
}

static int
decode_app_data(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree *sub_tree;
    sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 16, ett_app_data_unique_id, NULL, "unique_id");
    offset = decode_synode_no(tvb, offset, sub_tree, 
            hf_app_data_unique_id_group_id, hf_app_data_unique_id_msgno, hf_app_data_unique_id_node);

    proto_tree_add_item(pt, hf_app_data_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(pt, hf_app_data_lsn, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 16, ett_app_data_app_key, NULL, "app_key");
    offset = decode_synode_no(tvb, offset, sub_tree, 
            hf_app_data_app_key_group_id, hf_app_data_app_key_msgno, hf_app_data_app_key_node);

    proto_tree_add_item(pt, hf_app_data_consensus, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(pt, hf_app_data_expiry_time, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    //XDR_INLINE??

    proto_tree_add_item(pt, hf_app_data_notused, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(pt, hf_app_data_log_it, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(pt, hf_app_data_chosen, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(pt, hf_app_data_recover, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    gint32 saved_offset = offset;
    sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 0, ett_app_data_body, NULL, "body");
    offset = decode_app_data_body(tvb, offset, sub_tree);
    proto_item_set_len(sub_tree, offset - saved_offset);

    gint32 has_next;
    proto_tree_add_item_ret_uint(pt, hf_app_data_has_next, tvb, offset, 4, ENC_BIG_ENDIAN, &has_next);
    offset += 4;

    if (has_next > 0)
    {
        saved_offset = offset;
        sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 0, ett_app_data_next, NULL, "next");
        offset = decode_app_data(tvb, offset, sub_tree);
        proto_item_set_len(sub_tree, offset - saved_offset);
    }

    return offset;
}

static int 
decode_app_data_ptr(tvbuff_t *tvb, int offset, proto_tree *pt, gint _ett)
{
    gint32 exists = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;
    if (exists > 0)
    {
        proto_tree *sub_tree;
        int saved_offset = offset;
        sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 0, _ett, NULL, "next");
        offset = decode_app_data(tvb, offset, sub_tree);
        proto_item_set_len(sub_tree, offset - saved_offset);
    }
    return offset;
} 

static int
decode_snap(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree *sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 16, ett_snap_vers, NULL, "vers");
    offset = decode_synode_no(tvb, offset, sub_tree, 
        hf_snap_vers_group_id, hf_snap_vers_msgno, hf_snap_vers_node);

    gint32 snap_len = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;

    for (int i = 0; i < snap_len; ++i)
    {
        offset = decode_app_data_ptr(tvb, offset, sub_tree, ett_snap_snap);
    }

    offset = decode_uncommitted_list(tvb, offset, pt, hf_snap_u_list_uncommitted_list_active,
        ett_snap_u_list_uncommitted_list,
        hf_snap_u_list_uncommitted_list_group_id, 
        hf_snap_u_list_uncommitted_list_msgno, 
        hf_snap_u_list_uncommitted_list_node);

    return offset;
}

static int
decode_config(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree *sub_tree;
    sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 16, ett_gcs_snap_configs_start, NULL, "log_start");
    offset = decode_synode_no(tvb, offset, sub_tree, 
        hf_gcs_snap_configs_start_group_id, hf_gcs_snap_configs_start_msgno, hf_gcs_snap_configs_start_node);

    sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 16, ett_gcs_snap_configs_boot_key, NULL, "boot_key");
    offset = decode_synode_no(tvb, offset, sub_tree, 
        hf_gcs_snap_configs_boot_key_group_id, hf_gcs_snap_configs_boot_key_msgno, hf_gcs_snap_configs_boot_key_node);

    int saved_offset = offset;
    sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 0, ett_gcs_snap_configs_nodes, NULL, "nodes");
    offset = decode_node_list_1_1(tvb, offset, sub_tree,
        hf_gcs_snap_configs_nodes_address,
        hf_gcs_snap_configs_nodes_uuid,
        hf_gcs_snap_configs_nodes_min_proto,
        hf_gcs_snap_configs_nodes_max_proto);
    proto_item_set_len(sub_tree, offset - saved_offset);

    return offset;
}

static int 
decode_config_ptr(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    gint32 exists = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;
    if (exists > 0)
    {
        proto_tree *sub_tree;
        int saved_offset = offset;
        sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 0, ett_gcs_snap_configs, NULL, "config");
        offset = decode_config(tvb, offset, sub_tree);
        proto_item_set_len(sub_tree, offset - saved_offset);
    }
    return offset;
} 

static int 
decode_configs(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    gint32 len = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;

    for (int i = 0; i < len; ++i)
    {
        offset = decode_config_ptr(tvb, offset, pt);
    }
    return offset;
}

static int
decode_gcs_snap(tvbuff_t *tvb, int offset, proto_tree *pt)
{
    proto_tree *sub_tree = proto_tree_add_subtree_format(pt, tvb, offset, 16, ett_gcs_snap_log_start, NULL, "log_start");
    offset = decode_synode_no(tvb, offset, sub_tree, 
        hf_gcs_snap_log_start_group_id, hf_gcs_snap_log_start_msgno, hf_gcs_snap_log_start_node);

    offset = decode_configs(tvb, offset, pt);
    offset = decode_bytes(tvb, offset, pt, hf_gcs_snap_app_snap);
    return offset;
}

static guint
get_mgr_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	guint32 length = tvb_get_ntohl(tvb, offset + 4);
	return length + MGR_FRAME_HEADER_LEN;
}

static int
dissect_mgr_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    proto_tree *sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MGR");
    col_clear(pinfo->cinfo, COL_INFO);

    //add a subtree
    proto_item *ti = proto_tree_add_item(tree, proto_mgr, tvb, 0, -1, ENC_NA);
    proto_tree *mgr_tree = proto_item_add_subtree(ti, ett_mgr);

    //start decoding
    gint offset = 0;

    guint32 protocol_version;
    proto_tree_add_item_ret_uint(mgr_tree, hf_protocol_version, tvb, offset, 4, ENC_BIG_ENDIAN, &protocol_version);
    offset += 4;

    guint32 header_length;
    proto_tree_add_item_ret_uint(mgr_tree, hf_header_length, tvb, offset, 4, ENC_BIG_ENDIAN, &header_length);
    offset += 4;

    guint32 header_xtype;
    proto_tree_add_item_ret_uint(mgr_tree, hf_header_xtype, tvb, offset, 1, ENC_BIG_ENDIAN, &header_xtype);
    offset += 1;

    guint32 tag;
    proto_tree_add_item_ret_uint(mgr_tree, hf_header_tag, tvb, offset, 2, ENC_BIG_ENDIAN, &tag);
    offset += 2;

    //NULL byte
    offset += 1;

    if (header_length > 0) 
    {
    	proto_tree_add_item(mgr_tree, hf_to_node_no, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

    	proto_tree_add_item(mgr_tree, hf_from_node_no, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

    	proto_tree_add_item(mgr_tree, hf_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

        sub_tree = proto_tree_add_subtree_format(mgr_tree, tvb, offset, 16, ett_max_synode, NULL, "max_synode");
        offset = decode_synode_no(tvb, offset, sub_tree, 
            hf_max_synode_group_id, hf_max_synode_msgno, hf_max_synode_node);

    	proto_tree_add_item(mgr_tree, hf_start_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

        sub_tree = proto_tree_add_subtree_format(mgr_tree, tvb, offset, 16, ett_reply_to, NULL, "reply_to");
        offset = decode_ballot(tvb, offset, sub_tree, 
            hf_reply_to_cnt, hf_reply_to_node);

        sub_tree = proto_tree_add_subtree_format(mgr_tree, tvb, offset, 16, ett_proposal, NULL, "proposal");
        offset = decode_ballot(tvb, offset, sub_tree, 
            hf_proposal_cnt, hf_proposal_node);

    	proto_tree_add_item(mgr_tree, hf_op, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

        sub_tree = proto_tree_add_subtree_format(mgr_tree, tvb, offset, 16, ett_synode, NULL, "synode");
        offset = decode_synode_no(tvb, offset, sub_tree, 
            hf_synode_group_id, hf_synode_msgno, hf_synode_node);
    	
    	proto_tree_add_item(mgr_tree, hf_msg_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

    	gint32 receivers_exists = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    	offset += 4;
    	if (receivers_exists > 0)
    	{
            gint32 bitmap_length = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
            offset += 4;

    		proto_tree_add_bytes_format(mgr_tree, hf_receivers, tvb, offset, 4*bitmap_length,
	                tvb_get_ptr(tvb, offset, 4*bitmap_length), "Receiver");
	        offset += 4*bitmap_length;
    	}

    	gint32 app_data_exists = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    	offset += 4;
    	if (app_data_exists > 0)
    	{
            sub_tree = proto_tree_add_subtree_format(mgr_tree, tvb, offset, 0, ett_app_data, NULL, "app_data");
            gint32 saved_offset = offset;
            offset = decode_app_data(tvb, offset, sub_tree);
            proto_item_set_len(sub_tree, offset - saved_offset);
    	}

    	gint32 snap_exists = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    	offset += 4;
    	if (snap_exists > 0)
    	{
            sub_tree = proto_tree_add_subtree_format(mgr_tree, tvb, offset, 0, ett_snap, NULL, "snap");
            gint32 saved_offset = offset;
            offset = decode_snap(tvb, offset, sub_tree);
            proto_item_set_len(sub_tree, offset - saved_offset);
    	}

    	gint32 gcs_snap_exists = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    	offset += 4;
    	if (gcs_snap_exists > 0)
    	{
            sub_tree = proto_tree_add_subtree_format(mgr_tree, tvb, offset, 0, ett_snap, NULL, "gcs_snap");
            gint32 saved_offset = offset;
            offset = decode_gcs_snap(tvb, offset, sub_tree);
            proto_item_set_len(sub_tree, offset - saved_offset);
    	}

    	proto_tree_add_item(mgr_tree, hf_cli_err, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

    	proto_tree_add_item(mgr_tree, hf_force_delivery, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

    	proto_tree_add_item(mgr_tree, hf_refcnt, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

    	proto_tree_add_item(mgr_tree, hf_delivered_msg_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset += 4;

    	proto_tree_add_item(mgr_tree, hf_delivered_msg_msgno, tvb, offset, 8, ENC_BIG_ENDIAN);
    	offset += 8;
        
	    proto_tree_add_item(mgr_tree, hf_delivered_msg_node, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return tvb_captured_length(tvb);
}

static int
dissect_mgr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MGR_FRAME_HEADER_LEN,
        get_mgr_pdu_len, dissect_mgr_pdu, data);
    return tvb_reported_length(tvb);
}

void
proto_register_mysql_group_replication(void)
{
    proto_mgr = proto_register_protocol (
        "MySQL Group Replication", /* name        */
        "MySQL Group Replication", /* short name  */
        "mgr"           /* filter_name */
        );

    proto_register_field_array(proto_mgr, header_infos, array_length(header_infos));
    proto_register_subtree_array(etts, array_length(etts));
}

void
proto_reg_handoff_mysql_group_replication(void)
{
    static dissector_handle_t mgr_handle;

    mgr_handle = create_dissector_handle(dissect_mgr, proto_mgr);
    dissector_add_uint("tcp.port", MGR_DEFAULT_PORT, mgr_handle);
}
