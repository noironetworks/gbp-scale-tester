import trigger as tgr
import yaml

def execute_trigger():

    with open('triggers/triggers.yml', 'r') as trigger_yml:
	    trigger_cfg = yaml.load(trigger_yml)

    triggers = trigger_cfg['triggers']
    
    for trigger in triggers:
        trigger_id = trigger.keys()[0]
    	trigger_params = trigger.values()[0]
    	object_type = trigger_params['object_type']
    	event_type = trigger_params['event_type']
    	params = trigger_params['params']
        
        pre_trigger_verify_traffic(trigger_id)
        
        tgr.trigger(object_type, event_type, params)
        
        post_trigger_verify_traffic(trigger_id)

def pre_trigger_verify_traffic(trigger_id):
    pass     

def post_trigger_verify_traffic(trigger_id):
	pass


def main():
	execute_trigger()

if __name__ == '__main__':
	main()