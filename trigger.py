from libs import gbp_libs

"""
    object_type values could be,
    1. GBPPolicyAction
    2. GBPPolicyClassifier
    3. GBPPolicyRule

    event_type values could be,
    1. add
    2. update
    3. delete

    trigger_params vary for different objects and event_type
    {
        GBPPolicyAction: {
                    add: [name, description, action, tenant_id], 
                    update: [name, description, action_type, tenant_id], 
                    delete: [name]
        },
        GBPPolicyClassifier: {
                    add: [name, protocol, port_range, direction, tenant_id],
                    update: [name, protocol, port_range, direction, tenant_id],
                    delete: [name]
        },

    }
"""

def trigger(object_type, event_type, trigger_params):
	module = __import__('libs.gbp_libs', globals(), locals(), ['gbp_libs'], -1)
	class_ = getattr(module, object_type)
	instance = class_()
	#method = getattr(instance, event_type)
	getattr(instance, event_type)(trigger_params)
	#method.__call__(trigger_params)
	

def main():
	#trigger('GBPPolicyAction', 'add', { 'name': 'sabdha-action-allow', 'description': 'Test action from script', 'action':'allow', 'tenant_id': 'f1221082289c42268b6552a294a7ddc9'})
	trigger('GBPPolicyClassifier', 'update', {'name': 'SG-TCP-MySQL','protocol': 'TCP', 'port_range': '3306', 'direction': 'in', 'tenant_id': 'f1221082289c42268b6552a294a7ddc9'})
	#trigger('GBPPolicyRule', 'delete', {'name': 'allow-tcp-mysql'})
	#trigger('GBPPolicyRule', 'add', {'name': 'allow-tcp-mysql', 'description': 'Test policy rule from script', 'policy_classifier': 'SG-TCP-MySQL', 'policy_action': 'sabdha-action-allow', 'tenant_id': 'f1221082289c42268b6552a294a7ddc9'})
    #trigger('GBPPolicyRuleSet', 'add', {'name': 'linux-mysql-prs', 'description': 'Test Policy Rule Set from script', 'rule_list': ['allow-udp-snmp', 'allow-tcp-mysql'], 'tenant_id': 'f1221082289c42268b6552a294a7ddc9'})
if __name__ == '__main__':
	main()

