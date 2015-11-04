from abc import ABCMeta, abstractmethod
from keystoneclient.v2_0 import client as ksc
from neutronclient.neutron import client as nwc
from gbpclient.v2_0 import client as gbpc

ks_auth_url = 'http://10.30.120.50:5000/v2.0'
ks_user = 'admin'
ks_password = 'noir0123'
ks_tenant = 'admin'


def get_gbp_client():
    gbpclient = gbpc.Client(username=ks_user, password=ks_password,
                            tenant_name=ks_tenant, auth_url=ks_auth_url)
    return gbpclient

gbpclient = get_gbp_client()


class GBPObject(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def add(self):
        raise NotImplementedError("abstract method needs to be implemented")

    @abstractmethod
    def update(self):
        raise NotImplementedError("abstract method needs to be implemented")

    @abstractmethod
    def delete(self):
        raise NotImplementedError("abstract method needs to be implemented")

    @abstractmethod
    def list(self):
        raise NotImplementedError("abstract method needs to be implemented")




class GBPPolicyAction(GBPObject):
    """
     
        Possible params for Policy-Action
        {
        'name' : '<string>',
        'description': '<string> Optional',
        'action_type': '<string> allow | redirect | log | copy ',
        'shared': '<boolen> True | False' Optional,
        'tenant_id': '<uuid> Optional'
        }

    """

    def add(self, params):
        data = params['policy_action']
        body = {'policy_action': data}
        gbpclient.create_policy_action(body)

    def update(self, params):
        pass

    def delete(self, params):
        action_id = self.list(params)['id']        
        gbpclient.delete_policy_action(action_id)

    def list(self, params):
        if params['name']:
            for action in gbpclient.list_policy_actions()['policy_actions']:
                if action['name'] == params['name']:
                    return action
        else:
            return gbpclient.list_policy_actions()['policy_actions']
            
             


class GBPPolicyClassifier(GBPObject):

    """
     
        Possible params for Policy-Classifier
        {
        'name' : '<string>',
        'description': '<string> Optional',
        'protocol': '<string> tcp | udp | icmp | http | https | smtp | dns | ftp | any',
        'port_range': '<string> eg., 5000:6000 | 5000',
        'direction': '<string> in | out | bi'
        'shared': '<boolen> True | False' Optional,
        'tenant_id': '<uuid> Optional'
        }

    """

    def add(self, params):
        data = params['policy_classifier']
        
        body = {'policy_classifier': data}
        gbpclient.create_policy_classifier(body)

    def update(self, params):
        classifier_id = self.list(params)['id']
        data = params['policy_classifier']
        body = {'policy_classifier': data }
        gbpclient.update_policy_classifier(classifier_id, body)

    def delete(self, params):
        classifier_id = self.list(params)['id']
        gbpclient.delete_policy_classifier(classifier_id)

    def list(self, params):
        if params['name']:
            for classifier in gbpclient.list_policy_classifiers()['policy_classifiers']:
                if classifier['name'] == params['name']:
                    return classifier
        else:
            return gbpclient.list_policy_classifiers()['policy_classifiers']


class GBPPolicyRule(GBPObject):

    policy_action = GBPPolicyAction()
    policy_classifier = GBPPolicyClassifier()

    def add(self, params):
        
        data = {'name': params['policy_rule']['name'],
                'description': params['policy_rule']['description'],
                'policy_classifier_id': self.policy_classifier.list({'name': params['policy_rule']['policy_classifier_id']})['id'],
                'policy_actions': [ self.policy_action.list({'name': params['policy_rule']['policy_actions']})['id']],
                'tenant_id': params['policy_rule']['tenant_id']
                }
        body = {'policy_rule': data}
        gbpclient.create_policy_rule(body)

    def update(self, params):
        policy_rule_id = self.list(params)['id']
        data = {'name': params['policy_rule']['name'],
                'description': params['policy_rule']['description'],
                'policy_classifier_id': self.policy_classifier.list({'name': params['policy_rule']['policy_classifier_id']})['id'],
                'policy_actions': [ self.policy_action.list({'name': params['policy_rule']['policy_actions']})['id']]
        }
        body = {'policy_rule': data}
        gbpclient.update_policy_rule(policy_rule_id, body)

    def delete(self, params):
        policy_rule_id = self.list(params)['id']
        gbpclient.delete_policy_rule(policy_rule_id)

    def list(self, params):
        if params['name']:
            for rule in gbpclient.list_policy_rules()['policy_rules']:
                if rule['name'] == params['name']:
                    return rule
        else:
            return gbpclient.list_policy_rules()['policy_rules']

class GBPPolicyRuleSet(GBPObject):
    policy_rule = GBPPolicyRule()
    def add(self, params):
        
        data = {'name': params['policy_rule_set']['name'],
                'description': params['policy_rule_set']['description'],
                'policy_rules': [ self.policy_rule.list({'name': rule})['id'] for rule in params['policy_rule_set']['policy_rules'] ],
                'tenant_id': params['policy_rule_set']['tenant_id']
        }

        body = {'policy_rule_set': data}
        gbpclient.create_policy_rule_set(body)


    def update(self, params):
        policy_rule_set_id = self.list(params)['id']
        data = {'name': params['policy_rule_set']['name'],
                'description': params['policy_rule_set']['description'],
                'policy_rules': [ self.policy_rule.list({'name': rule})['id'] for rule in params['policy_rule_set']['policy_rules'] ]
        }
        body = {'policy_rule_set': data}
        gbpclient.update_policy_rule_set(policy_rule_set_id, body)

    def delete(self, params):
        policy_rule_set_id = self.list(params)['id']
        gbpclient.delete_policy_rule_set(policy_rule_set_id)

    def list(self, params):
        if params['name']:
            for rule_set in gbpclient.list_policy_rule_sets()['policy_rule_sets']:
                if rule_set['name'] == params['name']:
                    return rule_set
        else:
            return gbpclient.list_policy_rule_sets()['policy_rule_sets']

class GBPPolicyTargetGroup(GBPObject):

    def add(self, params):
        pass

    def update(self, params):
        pass

    def delete(self, params):
        pass

    def list(self, params):
        pass


class GBPL2Policy(GBPObject):

    def add(self, params):
        pass

    def update(self, params):
        pass

    def delete(self, params):
        pass

    def list(self, params):
        pass

class GBPL3Policy(GBPObject):

    def add(self, params):
        data = params['l3_policy']

        body = {'l3_policy': data}
        gbpclient.create_l3_policy(body)

    def update(self, params):
        l3_policy_id = self.list(params)['id']
        data = params['l3_policy']
        body = {'l3_policy': data}
        gbpclient.update_l3_policy(l3_policy_id, body)

    def delete(self, params):
        l3_policy_id = self.list(params)['id']
        gbpclient.delete_policy_l3_policy(l3_policy_id)

    def list(self, params):
        if params['name']:
            for l3_policy in gbpclient.list_l3_policies()['l3_policies']:
                if l3_policy['name'] == params['name']:
                    return l3_policy
        else:
            return gbpclient.list_l3_policies()['l3_policies']




