import os
import sys
import logging
from keystoneclient.v2_0 import client as ksc
from neutronclient.neutron import client as nwc
from gbpclient.v2_0 import client as gbpc

###
# This needs to be merged with libs/gbp_libs
###

class OSUtils(object):

    def __init__(self, config):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.ks_user = config['default']['keystone_user']
        self.ks_pass = config['default']['keystone_password']
        self.ks_auth_url = config['default']['keystone_auth_url']
        self.ks_tenant_name = config['default']['keystone_tenant_name']
        self.ks = ksc.Client(

            username=self.ks_user,
            password=self.ks_pass,
            tenant_name=self.ks_tenant_name,
            auth_url=self.ks_auth_url
        )

        self.nwclient = self.get_neutron_client()
        self.gbpclient = self.get_gbp_client()

    """
        Returns the handle for neutron-client
    """

    def get_neutron_client(self):
        nwclient = nwc.Client(
            '2.0',
            username=self.ks_user,
            password=self.ks_pass,
            tenant_name=self.ks_tenant_name,
            auth_url=self.ks_auth_url
        )
        return nwclient

    """
        Returns the handle for gbpclient
    """

    def get_gbp_client(self):
        gbpclient = gbpc.Client(username=self.ks_user, password=self.ks_pass,
                                tenant_name=self.ks_tenant_name, auth_url=self.ks_auth_url)
        return gbpclient

    """
        Returns the tenant info in the following format
        {
         tenant1_id : tenant1_name,
         tenant2_id : tenant2_name,
         .
         .
         . ,
         tenantn_id : tenantn_name
        }
    """

    def get_tenants_list(self):
        self.logger.info('Get tenant list from Keystone')
        tenants = self.ks.tenants.list()
        self.logger.info(tenants)
        if self.config['tenants']['tenants'] == 'all':
            return { tenant.id : tenant.name for tenant in tenants if tenant.enabled }
        return {tenant.id: tenant.name for tenant in tenants if tenant.enabled and tenant.name in self.config['tenants']['tenants']}

    """
        Returns the gbp policy-target-groups for all tenants

    """

    def get_gbp_ptgs_by_tenant_all(self, tenants):
        ptg_list_by_tenant_all = {}
        ptgs = self.gbpclient.list_policy_target_groups(
        )['policy_target_groups']
        for tenant_id, tenant_name in tenants.items():
            output = list(filter(lambda d: d['tenant_id'] == tenant_id, ptgs))
            ptg_list_by_tenant_all[tenant_name] = output
        return ptg_list_by_tenant_all

    """
        Returns the gbp policy-rule-set for all tenants

    """

    def get_gbp_prs_by_tenant_all(self, tenants):
        prs_list_by_tenant_all = {}
        prs_list = self.gbpclient.list_policy_rule_sets()['policy_rule_sets']
        for tenant_id, tenant_name in tenants.items():

            output = list(
                filter(lambda d: d['tenant_id'] == tenant_id, prs_list))
            prs_list_by_tenant_all[tenant_name] = output
        return prs_list_by_tenant_all

    """
        Returns the gbp policy-target-groups in the following format
        [{ ptg-1 },{ ptg-2 },...,{ ptg-n }]
    """

    def get_gbp_ptgs(self):
        ptgs = self.gbpclient.list_policy_target_groups(
        )['policy_target_groups']
        return ptgs

    """
        Returns the gbp policy-rule-sets in the following format
        [{ prs-1 }, { prs-2 },....,{ prs-n }]
    """

    def get_gbp_prss(self):
        prss = self.gbpclient.list_policy_rule_sets()['policy_rule_sets']
        return prss

    def get_fixed_ip_floating_ip_map(self):
        floating_ips = self.nwclient.list_floatingips()['floatingips']
        fixed_ip_floating_ip_map = {}
        for floating_ip_dict in floating_ips:
            fixed_ip = floating_ip_dict['fixed_ip_address']
            floating_ip = floating_ip_dict['floating_ip_address']
            if fixed_ip_floating_ip_map.has_key(fixed_ip):
                floating_ip_list = fixed_ip_floating_ip_map[fixed_ip]
                new_floating_ip_list = [floating_ip]
                final_floating_ip_list = floating_ip_list + \
                    new_floating_ip_list
                fixed_ip_floating_ip_map[fixed_ip] = final_floating_ip_list
            else:
                fixed_ip_floating_ip_map[fixed_ip] = [floating_ip]

        return fixed_ip_floating_ip_map

    def get_floating_ip(self, fixed_ip, floating_ip_map):
        if floating_ip_map.has_key(fixed_ip):
            floating_ip_list = floating_ip_map[fixed_ip]

            for floating_ip in floating_ip_list:
                if floating_ip.startswith(self.config['traffic']['floating_ip_subnet']):
                    return {'fixed_ip': fixed_ip, 'floating_ip': floating_ip}

        else:
            floating_ip = None
            return {'fixed_ip': fixed_ip, 'floating_ip': None}

    def get_fixed_ip(self, floating_ip, floating_ip_map):
        for fixed_ip, floating_ip_list in floating_ip_map.items():
            if floating_ip in floating_ip_list:
                return fixed_ip

    def get_gbp_ip(self, ptlist, floating_ip_map=None):

        pt_ip_list = []
        pt_nic_list = []
        for pt in ptlist:

            policy_target = self.gbpclient.show_policy_target(
                pt)['policy_target']
            policy_target_port_id = policy_target['port_id']
            policy_target_port = self.nwclient.show_port(
                policy_target_port_id)['port']

            policy_target_nics = policy_target_port['fixed_ips']
            pt_nic_list.append(policy_target_nics)

        for nic_list in pt_nic_list:

            for nic in nic_list:

                if self.config['traffic']['use_floating_ip'] == 'True':

                    floating_ip = self.get_floating_ip(
                        nic['ip_address'], floating_ip_map)

                    if floating_ip:
                        pt_ip_list.append(
                            self.get_floating_ip(nic['ip_address'], floating_ip_map))
                else:
                    pt_ip_list.append({'fixed_ip': nic['ip_address']})



        return pt_ip_list

    def get_gbp_policy_rules(self, prs):
        contract_list = []
        pr = []
        prule_list = self.gbpclient.show_policy_rule_set(prs)
        for k, v in prule_list.items():
            for i, j in v.items():
                if (i == 'policy_rules'):
                    pr = j

        for PolicyRule in pr:
            contract_details = {}
            prule = self.gbpclient.show_policy_rule(PolicyRule)
            for k, v in prule.items():
                for i, j in v.items():
                    if (i == 'policy_classifier_id'):
                        ClassifierId = j
                        PolicyClassifier = self.gbpclient.show_policy_classifier(
                            ClassifierId)
                        for pol_class in PolicyClassifier.values():
                            contract_details['name'] = pol_class.get('name')
                            contract_details[
                                'protocol'] = pol_class.get('protocol')
                            contract_details[
                                'port'] = pol_class.get('port_range')
                            contract_details[
                                'direction'] = pol_class.get('direction')

                    if (i == 'policy_actions'):
                        ActionId = j
                        for action in ActionId:
                            PolicyAction = self.gbpclient.show_policy_action(
                                action)
                            for pol_act in PolicyAction.values():
                                contract_details['action'] = pol_act.get(
                                    'action_type')
            contract_list.append(contract_details)
        return contract_list
