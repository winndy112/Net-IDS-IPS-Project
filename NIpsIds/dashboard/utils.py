import netifaces

def get_interfaces():
    try:
        interfaces = netifaces.interfaces()
        return [interface for interface in interfaces if interface != 'lo']
    except Exception as e:
        return []