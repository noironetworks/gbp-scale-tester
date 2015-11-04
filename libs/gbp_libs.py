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

    def add(self, params):
        data = {'name': params['name'],
                'description': params['description'],
                'action_type': params['action'],
                'tenant_id': params['tenant_id']
                }
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

    def add(self, params):
        data = {'name': params['name'],
                'protocol': params['protocol'],
                'port_range': params['port_range'],
                'direction': params['direction'],
                'tenant_id': params['tenant_id']
                }
        
        body = {'policy_classifier': data}
        gbpclient.create_policy_classifier(body)

    def update(self, params):
        classifier_id = self.list(params)['id']
        data = {'name': params['name'],
                'protocol': params['protocol'],
                'port_range': params['port_range'],
                'direction': params['direction']                 
        }
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
        
        data = {'name': params['name'],
                'description': params['description'],
                'policy_classifier_id': self.policy_classifier.list({'name': params['policy_classifier']})['id'],
                'policy_actions': [ self.policy_action.list({'name': params['policy_action']})['id']],
                'tenant_id': params['tenant_id']
                }
        body = {'policy_rule': data}
        gbpclient.create_policy_rule(body)

    def update(self, params):
        policy_rule_id = self.list(params)['id']
        data = {'name': params['name'],
                'description': params['description'],
                'policy_classifier_id': self.policy_classifier.list({'name': params['policy_classifier']})['id'],
                'policy_actions': [ self.policy_action.list({'name': params['policy_action']})['id']]
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
        
        data = {'name': params['name'],
                'description': params['description'],
                'policy_rules': [ self.policy_rule.list({'name': rule})['id'] for rule in params['rule_list'] ],
                'tenant_id': params['tenant_id']
        }

        body = {'policy_rule_set': data}
        gbpclient.create_policy_rule_set(body)


    def update(self, params):
        policy_rule_set_id = self.list(params)['id']
        data = {'name': params['name'],
                'description': params['description'],
                'policy_rules': [ self.policy_rule.list({'name': rule})['id'] for rule in params['rule_list'] ]
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


class GBPL3Policy(GBPObject):

    def add(self, params):
        pass

    def update(self, params):
        pass

    def delete(self, params):
        pass

    def list(self, params):
        pass

    

