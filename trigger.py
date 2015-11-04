from libs import gbp_libs

def trigger(object_type, event_type, trigger_params):
	module = __import__('libs.gbp_libs', globals(), locals(), ['gbp_libs'], -1)
	class_ = getattr(module, object_type)
	instance = class_()
	#method = getattr(instance, event_type)
	getattr(instance, event_type)(trigger_params)
	#method.__call__(trigger_params)
	


