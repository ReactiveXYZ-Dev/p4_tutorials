#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import json
import pickle
from time import sleep
from collections import defaultdict
import threading

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(
                    table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(
                    action_name, p.param_id),
                print '%r' % p.value,
            print

def writeDropEntry(p4info_helper, sw, table_name):
    drop_entry = p4info_helper.buildTableEntry(
        table_name= "MyIngress." + table_name,
        default_action = True,
        action_name = "MyIngress.drop",
        action_params = {}
    )
    sw.WriteTableEntry(drop_entry)
    return drop_entry

def writeTableEntry(p4info_helper, sw, table_name, dst_eth_addr, dst_eth_port, dst_ip_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress." + table_name,
        match_fields = {
            "hdr.ipv4.dstAddr": [dst_ip_addr, 32]
        },
        action_name = "MyIngress.ipv4_forward",
        action_params = {
            "dstAddr": dst_eth_addr,
            "port": dst_eth_port
        }
    )
    sw.WriteTableEntry(table_entry)
    return table_entry

def printDigests(p4info_helper, sw):
    print "Start checking digests for %s" % sw.device_id
    for msg in sw.StreamDigestMessages():
        if msg.has_digest():
            print("Digest: ", msg.digest())


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt'    
        )

        switches = {
            0: s1,
            1: s2,
            2: s3
        }

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s3"

        
        # deal with table entries
        TABLE_NAME = "ipv4_lpm"
        # from_sw:{ to_sw: [rules] }
        accept_rules = defaultdict(dict)

        # start print digest in a separate thread
        for _, sw in switches.items():
            t = threading.Thread(target=printDigests, args=(p4info_helper, sw))
            t.start()

        while True:
            rule = raw_input("# Please enter a command: ")
            rules = rule.split(" ")
            rule = rules[0]

            if rule == 'drop':
                if len(rules) > 1:
                    from_sw_id, to_sw_id = int(rules[1]), int(rules[2])
                    if to_sw_id not in accept_rules[from_sw_id]:
                        print "There's no allowed traffic from switch %s to %s" % (from_sw_id, to_sw_id)
                    else:
                        switches[from_sw_id].DeleteTableEntry(accept_rules[from_sw_id][to_sw_id])
                        accept_rules[from_sw_id].pop(to_sw_id, None)
                        print "Connection from %s to %s dropped" % (from_sw_id, to_sw_id)
                else:
                    # write all drop table rules
                    writeDropEntry(p4info_helper, s1, TABLE_NAME)
                    writeDropEntry(p4info_helper, s2, TABLE_NAME)
                    writeDropEntry(p4info_helper, s3, TABLE_NAME)
                    print "Installed drop rules on s1, s2, s3"
            elif rule == 'accept':
                if s1.device_id not in accept_rules[s1.device_id]:
                    r = writeTableEntry(p4info_helper, s1, TABLE_NAME,
                            "00:00:00:00:01:01", 1, "10.0.1.1")
                    accept_rules[s1.device_id][s1.device_id] = r
                else:
                    print "Already allow traffic from switch %s to %s" % (s1.device_id, s1.device_id)
                if s2.device_id not in accept_rules[s1.device_id]:
                    r = writeTableEntry(p4info_helper, s1, TABLE_NAME,
                                "00:00:00:02:02:00", 2, "10.0.2.2")
                    accept_rules[s1.device_id][s2.device_id] = r
                else:
                    print "Already allow traffic from switch %s to %s" % (
                        s1.device_id, s2.device_id)
                if s3.device_id not in accept_rules[s1.device_id]:
                    r = writeTableEntry(p4info_helper, s1, TABLE_NAME,
                                "00:00:00:03:03:00", 3, "10.0.3.3")
                    accept_rules[s1.device_id][s3.device_id] = r
                else:
                    print "Already allow traffic from switch %s to %s" % (
                        s1.device_id, s3.device_id)
                print "Installed transit rules for s1"

                if s1.device_id not in accept_rules[s2.device_id]:
                    r = writeTableEntry(p4info_helper, s2, TABLE_NAME,
                                "00:00:00:01:01:00", 2, "10.0.1.1")
                    accept_rules[s2.device_id][s1.device_id] = r
                else:
                    print "Already allow traffic from switch %s to %s" % (
                        s2.device_id, s1.device_id)
                if s2.device_id not in accept_rules[s2.device_id]:
                    r = writeTableEntry(p4info_helper, s2, TABLE_NAME,
                                "00:00:00:00:02:02", 1, "10.0.2.2")
                    accept_rules[s2.device_id][s2.device_id] = r
                else:
                    print "Already allow traffic from switch %s to %s" % (
                        s2.device_id, s2.device_id)
                if s3.device_id not in accept_rules[s2.device_id]:
                    r = writeTableEntry(p4info_helper, s2, TABLE_NAME,
                                "00:00:00:03:03:00", 3, "10.0.3.3")
                    accept_rules[s2.device_id][s3.device_id] = r
                else:
                    print "Already allow traffic from switch %s to %s" % (
                        s2.device_id, s3.device_id)
                print "Installed transit rules for s2"

                if s1.device_id not in accept_rules[s3.device_id]:
                    r = writeTableEntry(p4info_helper, s3, TABLE_NAME,
                                "00:00:00:01:01:00", 2, "10.0.1.1")
                    accept_rules[s3.device_id][s1.device_id] = r
                else:
                    print "Already allow traffic from switch %s to %s" % (
                        s3.device_id, s1.device_id)
                if s2.device_id not in accept_rules[s3.device_id]:
                    r = writeTableEntry(p4info_helper, s3, TABLE_NAME,
                                "00:00:00:02:02:00", 3, "10.0.2.2")
                    accept_rules[s3.device_id][s2.device_id] = r
                else:
                    print "Already allow traffic from switch %s to %s" % (
                        s3.device_id, s2.device_id)
                if s3.device_id not in accept_rules[s3.device_id]:
                    r = writeTableEntry(p4info_helper, s3, TABLE_NAME,
                                "00:00:00:00:03:03", 1, "10.0.3.3")
                    accept_rules[s3.device_id][s3.device_id] = r
                else:
                    print "Already allow traffic from switch %s to %s" % (
                        s3.device_id, s3.device_id)
                print "Installed transit rules for s3"
            
            # read table rules
            readTableRules(p4info_helper, s1)
            readTableRules(p4info_helper, s2)
            readTableRules(p4info_helper, s3)

    except grpc.RpcError as e:
        printGrpcError(e)
    except KeyboardInterrupt:
        print " Shutting down."
    
    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/firewall.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/firewall.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    
    main(args.p4info, args.bmv2_json)
