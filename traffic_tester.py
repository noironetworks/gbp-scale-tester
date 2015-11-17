import logging
import logging.config
import datetime
from libs import os_get_env as os_lib
from libs import traf_tester as remote_libs
from configobj import ConfigObj
from argparse import ArgumentParser

logging.config.fileConfig('conf/logging.ini')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

action_list = ['start', 'stop']
parser = ArgumentParser(description="Datapath traffic testing")
parser.add_argument("-f", "--cfgfile", required=True, metavar="FILE")
parser.add_argument("-a", "--action", required=True)
parser.add_argument("-t", "--tid")
args = parser.parse_args()
cfgfile = args.cfgfile
config = ConfigObj(cfgfile)
action = args.action
tid = args.tid if args.tid else None

endpoints_list = []

osutils = os_lib.OSUtils(config)


def get_ptg_ip_list(ptg, floating_ip_map=None):
    tenant_ptg_member_ip_list = {}
    ip_list = []

    logger.info("Policy target by Policy target group")
    logger.info(ptg)

    for k, v in ptg.items():
        if(k == 'policy_targets'):
            if config['traffic']['use_floating_ip'] == 'True':

                ip_list = osutils.get_gbp_ip(v, floating_ip_map)
            else:
                ip_list = osutils.get_gbp_ip(v)
        tenant_ptg_member_ip_list[ptg['id']] = ip_list

    return tenant_ptg_member_ip_list


def get_policy_rule_per_tenant(tenant, ptg):
    contract_list = []
    for k, v in ptg.items():
        if(k == 'provided_policy_rule_sets'):
            contract_list = osutils.get_gbp_policy_rules(tenant, v)
    return contract_list


###############################################
# Dummy policy_rule_set for testing

def get_policy_rule_for_prs(tenant, prs):
    contract = [{'name': 'allow_ssh',
                 'protocol': 'tcp',
                 'port': 22,
                 'direction': 'in',
                 'action': 'allow'},
                {'name': 'allow_icmp',
                 'protocol': 'icmp',
                 'port': 'None',
                 'direction': 'in',
                 'action': 'allow'}]
    return contract


def get_default_icmp_contract():
    contract = [{'name': 'allow_icmp', 'protocol': 'icmp',
                 'port': 'None', 'direction': 'in', 'action': 'allow'}]
    return contract

###############################################


def get_traffic_testing_endpoint(
        src_tenant,
        dest_tenant,
        src_ptg,
        dest_ptg,
        src_eps,
        dest_eps,
        contract):
    endpoint = {'src_tenant': src_tenant,
                'dest_tenant': dest_tenant,
                'src_grp': src_ptg,
                'dest_grp': dest_ptg,
                'src_eps': src_eps,
                'dest_eps': dest_eps,
                'contract': contract
                }

    return endpoint


def get_src_ptgs_by_prs(tenant_id_list, ptgs, inter_tenant, prs=None):

    if prs:
        if inter_tenant:
            src_ptgs = [ptg for ptg in ptgs if (prs['id']
                                                in ptg['consumed_policy_rule_sets'])]

        else:
            src_ptgs = [ptg for ptg in ptgs if (prs['id']
                                                in ptg['consumed_policy_rule_sets'] and ptg['tenant_id'] in tenant_id_list)]

        return src_ptgs
    else:
        src_ptgs = ptgs
        return src_ptgs


def get_dest_ptgs_by_prs(tenant_id_list, ptgs, inter_tenant, prs=None):
    if prs:
        if inter_tenant:
            dest_ptgs = [ptg for ptg in ptgs if (prs['id']
                                                 in ptg['provided_policy_rule_sets'])]

        else:
            dest_ptgs = [ptg for ptg in ptgs if (prs['id']
                                                 in ptg['provided_policy_rule_sets'] and ptg['tenant_id'] in tenant_id_list)]
        return dest_ptgs

    else:
        dest_ptgs = ptgs
        return dest_ptgs


def get_intra_tenant_intra_ptg_endpoints(ptgs, tenants, tenant_id_list, floating_ip_map):
    endpoints = []
    for ptg in ptgs:
        if ptg['tenant_id'] in tenant_id_list:
            if config['traffic']['ignore_ptg_pattern'] not in ptg['name']:
                
                if config['traffic']['use_floating_ip'] == 'True':

                    ptg_ip_list = get_ptg_ip_list(ptg, floating_ip_map)
                    ptg_ip_list = ptg_ip_list[ptg['id']]
                    src_ip_list = [ip_list['floating_ip']
                                   for ip_list in ptg_ip_list]
                    if config['traffic']['use_floating_ip_ping'] == 'True':
                        dest_ip_list = [ip_list['floating_ip']
                                        for ip_list in ptg_ip_list]
                    else:
                        dest_ip_list = [ip_list['fixed_ip']
                                        for ip_list in ptg_ip_list]
                else:
                    ptg_ip_list = get_ptg_ip_list(ptg)
                    ptg_ip_list = ptg_ip_list[ptg['id']]
                    src_ip_list = [ip_list['fixed_ip']
                                   for ip_list in ptg_ip_list]
                    dest_ip_list = src_ip_list
                contract = get_default_icmp_contract()
                endpoint = get_traffic_testing_endpoint(
                    tenants[ptg['tenant_id']], tenants[ptg['tenant_id']],
                    ptg['name'],
                    ptg['name'],
                    src_ip_list, dest_ip_list, contract)
                endpoints.append(endpoint)
    return endpoints


def get_prs_based_endpoints(ptgs, tenants, tenant_id_list, prss, inter_tenant, floating_ip_map):
    endpoints = []
    for prs in prss:

        src_ptg = {}
        dest_ptg = {}
        src_ptgs = get_src_ptgs_by_prs(tenant_id_list, ptgs, inter_tenant, prs)
        dest_ptgs = get_dest_ptgs_by_prs(
            tenant_id_list, ptgs, inter_tenant, prs)
        for ptg in src_ptgs:
            if config['traffic']['ignore_ptg_pattern'] not in ptg['name']:
                if config['traffic']['use_floating_ip'] == 'True':
                    src_ptg_ip_list = get_ptg_ip_list(
                        ptg, floating_ip_map)
                    src_ptg_ip_list = src_ptg_ip_list[ptg['id']]
                    src_ip_list = [ip_list['floating_ip']
                                   for ip_list in src_ptg_ip_list]

                else:
                    src_ptg_ip_list = get_ptg_ip_list(ptg)
                    src_ptg_ip_list = src_ptg_ip_list[ptg['id']]
                    src_ip_list = [ip_list['fixed_ip'] for ip_list in src_ptg_ip_list
                                   ]
                src_ptg_ip = {ptg['id']: src_ip_list}
                src_ptg.update(src_ptg_ip)

        for ptg in dest_ptgs:
            if config['traffic']['ignore_ptg_pattern'] not in ptg['name']:
                if config['traffic']['use_floating_ip'] == 'True':
                    dest_ptg_ip_list = get_ptg_ip_list(
                        ptg, floating_ip_map)
                    if config['traffic']['use_floating_ip_ping'] == 'True':
                        dest_ptg_ip_list = dest_ptg_ip_list[ptg['id']]
                        dest_ip_list = [ip_list['floating_ip']
                                        for ip_list in dest_ptg_ip_list]
                    else:
                        dest_ptg_ip_list = dest_ptg_ip_list[ptg['id']]
                        dest_ip_list = [ip_list['fixed_ip']
                                        for ip_list in dest_ptg_ip_list]

                else:
                    dest_ptg_ip_list = get_ptg_ip_list(ptg)
                    dest_ptg_ip_list = dest_ptg_ip_list[ptg['id']]
                    dest_ip_list = [ip_list['fixed_ip']
                                    for ip_list in dest_ptg_ip_list]
                dest_ptg_ip = {ptg['id']: dest_ip_list}
                dest_ptg.update(dest_ptg_ip)

        contract = get_default_icmp_contract()
        for srcptg in src_ptgs:

            if config['traffic']['ignore_ptg_pattern'] not in srcptg['name']:
                for destptg in dest_ptgs:
                    contract = osutils.get_gbp_policy_rules(prs['id'])
                    if config['traffic']['ignore_ptg_pattern'] not in destptg['name']:
                        endpoint = get_traffic_testing_endpoint(tenants[srcptg['tenant_id']], tenants[destptg['tenant_id']], srcptg['name'], destptg[
                                                                'name'], src_ptg[srcptg['id']], dest_ptg[destptg['id']], contract)
                        endpoints.append(endpoint)
    return endpoints


def get_intra_tenant_inter_ptg_endpoints(ptgs, tenants, tenant_id_list, prss, floating_ip_map):
    endpoints = get_prs_based_endpoints(
        ptgs, tenants, tenant_id_list, prss, False, floating_ip_map)
    return endpoints


def get_inter_tenant_endpoints(ptgs, tenants, tenant_id_list, prss, floating_ip_map):
    endpoints = get_prs_based_endpoints(
        ptgs, tenants, tenant_id_list, prss, True, floating_ip_map)
    return endpoints


def main():
    logger.info('Start the program')
    logger.info('Initialize OSUtils')


#    endpoints_list = []
    logger.info('\n\nGet tenant details\n\n')
    tenants = osutils.get_tenants_list()

    tenant_id_list = tenants.keys()
    logger.info(tenants)

    logger.info('\n\nGet policy-target-groups for all tenants\n\n')
    ptgs = osutils.get_gbp_ptgs()

    logger.info('\n\nGet policy-rule-sets for all tenants\n\n')
    prss = osutils.get_gbp_prss()

    floating_ip_map = {}

    if config['traffic']['use_floating_ip'] == 'True':

        floating_ip_map = osutils.get_fixed_ip_floating_ip_map()

        

    """
        Code to generate endpoints for with-in ptg traffic
    """
    intra_tenant_intra_ptg_endpoints = get_intra_tenant_intra_ptg_endpoints(
        ptgs, tenants, tenant_id_list, floating_ip_map)
    global endpoints_list
    endpoints_list = endpoints_list + intra_tenant_intra_ptg_endpoints

    """
        Code to generate the endpoints based on the policy-rulesets
    """
    # intra_tenant_inter_ptg_endpoints = get_intra_tenant_inter_ptg_endpoints(
    #     ptgs, tenants, tenant_id_list, prss, floating_ip_map)
    # global endpoints_list
    # endpoints_list = endpoints_list + intra_tenant_inter_ptg_endpoints

    """
        Code to generate the endpoints based on the policy-rulesets inter-tenant
    """
    # inter_tenant_inter_ptg_endpoints = get_inter_tenant_endpoints(
    #    ptgs, tenants, tenant_id_list, prss, floating_ip_map)
    #global endpoints_list
    #endpoints_list = endpoints_list + inter_tenant_inter_ptg_endpoints

    for endpoint in endpoints_list:
        logger.info("*" * 50)
        for k, v in endpoint.items():

            logger.info("%s: %s" % (k, v))
        logger.info("" * 100)

    if tid:
        remote_libs.start_task(
            config, endpoints_list, action, osutils, floating_ip_map, tid)
    else:
        remote_libs.start_task(config, endpoints_list, action)

if __name__ == '__main__':
    main()
