from fabric.api import *
import os
import json
import logging
import time
import re
from prettytable import PrettyTable

path = os.getcwd() + '/scripts'
os.path.join(path)

path = os.getcwd() + '/packages'
os.path.join(path)

test_results_path = '~/dp_test_results'
logger = logging.getLogger(__name__)


def setup_env(config, hosts):
    test_results_path = config['traffic']['test_results_path']
    test_method = config['traffic']['test_method']
    delta = config['traffic']['allowed_delta_percentage']
    env.hosts = hosts
    env.user = config['traffic']['remote_user']
    env.password = config['traffic']['remote_pass']
    env.skip_bad_hosts = True
    env.gateway = config['traffic']['ssh_gateway']
    env.warn_only = True
    logger.info("Initailized the environment with Endpoints")


def get_test_cmd(test_method):
    pass


def install_hping(environment):
    try:
        out = run(
            "python -c 'import platform; print platform.linux_distribution()[0]'")
        os_info = out
        logger.debug("Host %s runs %s" % (env.host_string, os_info))
        if out.return_code == 0:
            if os_info in [
    'CentOS',
    'Red Hat Enterprise Linux Server',
     'Fedora']:
                out = sudo("yum -y install hping3")
                if out.return_code == 0:
                    logger.info("Installed hping3 on %s" % (env.host_string))
            elif os_info in ['Ubuntu']:
                out = sudo("apt-get -y install hping3")
                if out.return_code == 0:
                    logger.info("Installed hping3 on %s" % (env.host_string))
        out = run("mkdir %s" % (test_results_path))
    except SystemExit, e:
        logger.warn("Exception while executing task: %s", str(e))


def install_iperf(environment):
    try:
        out = run("python -c 'import platform;"
                  " print platform.linux_distribution()[0]'")
        os_info = out
        logger.debug("Host %s runs %s" % (env.host_string, os_info))
        if out.return_code == 0:
            if os_info in ['CentOS',
                           'Red Hat Enterprise Linux Server',
                           'Fedora']:
                out = sudo("yum -y install iperf")
                if out.return_code == 0:
                    logger.info("Installed iperf on %s" % (env.host_string))

            elif os_info in ['Ubuntu', 'LinuxMint']:
                out = run('mkdir ~/packages')
                out = put('packages/*.deb', '~/packages/')
                out = sudo('dpkg -i /home/noiro/packages/libiperf*')
                out = sudo('dpkg -i /home/noiro/packages/iperf*')
                # out = sudo("apt-get -y install iperf")

                if out.return_code == 0:
                    logger.info("Installed iperf on %s" % (env.host_string))
        out = run("mkdir %s" % (test_results_path))
    except SystemExit, e:
        logger.warn("Exception while executing task: %s", str(e))


def pretty_table_content(config, data):
    print "The data for traffic output is:"
    print data
    print "after data"
    x = PrettyTable(["src_tenant",
                     "src_ep",
                     "dest_tenant",
                     "dest_ep",
                     "src_grp",
                     "dest_grp",
                     "packets_transmitted",
                     "packets received",
                     "packet_loss %",
                     #"rtt_min",
                     #"rtt_avg",
                     #"rtt_max",
                     "test_status"])

    x.align["src_tenant"] = "l"  # Left align source tenant values
    # One space between column edges and contents (default)
    x.padding_width = 1
    status = None
    dest_ep_regex = ".*-*-(?P<dest_ip>[0-9]+_[0-9]+_[0-9]+_[0-9]+)-.*"

    try:
        for endpoint_result in data:
            print "*"*100
            print "Endpoint result is: \n"
            print endpoint_result
            print "*"*100
            print endpoint_result
            for endpoint_id, content in endpoint_result.items():
                
                for k, v in content.items():
                    src_ep = k
                    src_tenant = v['endpoints']['src_tenant']
                    dest_tenant = v['endpoints']['dest_tenant']
                    src_grp = v['endpoints']['src_grp']
                    dest_grp = v['endpoints']['dest_grp']
                    if v['test_result']:
                        test_result_files = v['test_result'].keys()
                        for test_result_file in test_result_files:
                            if src_grp in test_result_file and dest_grp in test_result_file:
                                dest_ep_match = re.match(
                                    dest_ep_regex, test_result_file)
                                dest_ep = dest_ep_match.group('dest_ip')
                                packet_stats = \
                                    v['test_result'][test_result_file]['packet_stats']
                                packet_loss_percent = \
                                    packet_stats['packet_loss']  # NOQA
                                try:
                                    if (packet_loss_percent <= int(config['traffic']['allowed_delta_percentage'])):  # NOQA
                                        status = 'Success'
                                    else:
                                        status = 'Failed'
                                except ValueError:

                                    status = 'Failed'
                    

                                rtt_stats = v['test_result'][test_result_file]['rtt']
                                x.add_row([src_tenant, src_ep,
                                    dest_tenant, dest_ep.replace('_', '.'),
                                    src_grp, dest_grp,
                                    packet_stats['packets_transmitted'],
                                    packet_stats['packets_received'],
                                    packet_loss_percent,
                                    # rtt_stats['rtt_min'],
                                    # rtt_stats['rtt_avg'],
                                    # rtt_stats['rtt_max'],
                                    status])
                    else:
                        for dest_ep in v['endpoints']['dest_eps']:
                            x.add_row([src_tenant, src_ep, dest_tenant, dest_ep, src_grp,  dest_grp, '-', '-', '-','Failed'])
        print x

    except Exception as e:
        print "Error at pretty_table_content", e
        logger.info('Error at pretty_table_content')
        logger.warn(e)


def iperf_tcp_pretty_table_content(config, data):
    x = PrettyTable(["src_tenant",
                     "src_ep",
                     "dest_tenant",
                     "dest_ep",
                     "interval_time",
                     "transferred",
                     "bandwidth",
                     #"retr",
                     "test_status"])

    x.align["src_tenant"] = "l"  # Left align source tenant values
    # One space between column edges and contents (default)
    x.padding_width = 1
    status = None
    dest_ep_regex = ".*-*-(?P<dest_ip>[0-9]+_[0-9]+_[0-9]+_[0-9]+)-.*"

    # print "data is.....", data

    for content in data:
        print "CONTENT.............\n", content
        for k, v in content.items():
            src_ep = k
            src_tenant = v['src_tenant']
            dest_tenant = v['dest_tenant']
            test_result_files = v['test_result'].keys()
            for test_result_file in test_result_files:
                dest_ep_match = re.match(dest_ep_regex, test_result_file)
                dest_ep = dest_ep_match.group('dest_ip')
                bandwidth_stats = \
                    v['test_result'][test_result_file]['bandwidth_stats']
                if bandwidth_stats['interval_time'] and bandwidth_stats[
                    'transferred'] and bandwidth_stats['bandwidth']:
                    status = "Success"
                else:
                    status = "Failed"
            x.add_row([src_tenant, src_ep,
                           dest_tenant, dest_ep.replace('_', '.'),
                           bandwidth_stats['interval_time'],
                           bandwidth_stats['transferred'],
                           bandwidth_stats['bandwidth'],
                       #    bandwidth_stats['retr'],
                           status])
    print x


def iperf_udp_pretty_table_content(config, data):
    x = PrettyTable(["src_tenant",
                     "src_ep",
                     "dest_tenant",
                     "dest_ep",
                     "interval_time",
                     "transferred",
                     "bandwidth",
                     "jitter",
                     "loss_datagram",
                     "total_datagram",
                     "loss_percent",
                     "test_status"])

    x.align["src_tenant"] = "l"  # Left align source tenant values
    # One space between column edges and contents (default)
    x.padding_width = 1
    status = None
    dest_ep_regex = ".*-*-(?P<dest_ip>[0-9]+_[0-9]+_[0-9]+_[0-9]+)-.*"
    for content in data:
        for k, v in content.items():
            src_ep = k
            src_tenant = v['src_tenant']
            dest_tenant = v['dest_tenant']
            test_result_files = v['test_result'].keys()
            for test_result_file in test_result_files:
                dest_ep_match = re.match(dest_ep_regex, test_result_file)
                dest_ep = dest_ep_match.group('dest_ip')
                bandwidth_stats = \
                    v['test_result'][test_result_file]['bandwidth_stats']
                if bandwidth_stats['loss_percent'] != '':
                    bandwidth_loss_percent = \
                    bandwidth_stats['loss_percent'] + " %"  # NOQA
                else:
                    bandwidth_loss_percent = ""
                if bandwidth_stats['interval_time'] and bandwidth_stats[
                    'transferred'] and bandwidth_stats['bandwidth']:
                    status = "Success"
                else:
                    status = "Failed"
                x.add_row([src_tenant, src_ep,
                           dest_tenant, dest_ep.replace('_', '.'),
                           bandwidth_stats['interval_time'],
                           bandwidth_stats['transferred'],
                           bandwidth_stats['bandwidth'],
                           bandwidth_stats['jitter'],
                           bandwidth_stats['loss_datagram'],
                           bandwidth_stats['total_datagram'],

                           bandwidth_loss_percent,
                           status])
    print x





@task
@parallel
def create_test_results_directory(environment):
    try:
        out = run("mkdir %s" % (test_results_path))
    except SystemExit, e:
        logger.warn("Exception while executing task: %s", str(e))


@task
@parallel
def activate_backup_interface(environment, config):
    try:
        out = run(
            "ifconfig eth1 | grep 'inet addr' | awk -F : '{ print $2 }' | awk '{print $1}'")
        if not out:
            sudo("dhclient %s" % (config['traffic']['backup_ptg_interface']))
            backup_ptg_ip = run(
                "ifconfig eth1 | grep 'inet addr' | awk -F : '{ print $2 }' | awk '{print $1}'")
            if backup_ptg_ip:
                return backup_ptg_ip
        else:
            return out
    except SystemExit, e:
        logger.warn("Exception while executing task: %s", str(e))


@task
@parallel
def test_ping(environment, config, endpoints, contract, timestamp):
    try:
        for dest_ep in endpoints['dest_eps']:
            if dest_ep != env.host_string:

                #                sudo('hping3 %s --icmp --fast -q 2> testtraffic-%s-%s-%s.txt 1> /dev/null &' %
                #                     (dest_ep, env.host_string.replace('.', '_'), dest_ep.replace('.', '_'), timestamp), pty=False)

                sudo('ping %s 1> pingtraffic-%s-%s-%s-%s-%s-%s-%s.txt &' %
                     (dest_ep, endpoints['src_tenant'], endpoints['dest_tenant'], endpoints['src_grp'], endpoints['dest_grp'], env.host_string.replace('.', '_'), dest_ep.replace('.', '_'
                                                                                                                                                                                  ), timestamp), pty=False)

    except SystemExit, e:
        logger.warn("Exception while executing task: %s", exc_info=1)


@task
@parallel
def test_tcp_server(environment, config, endpoints, timestamp):
    print "TCP SERVER Testing Code"

    print "ENDPOINTS:", endpoints
    print env.hosts
    print "ENV HOST STRING......", env.host_string

    try:
        for dest_ep in endpoints:
            print "DEST EP", dest_ep
            if dest_ep == env.host_string:

                if (os.system("pgrep iperf") == 0):
                    pass
                else:
                    sudo("iperf -s -p 6005 -i 1 > tcptesttrafficserver-%s-%s.txt 2>&1 &" %
                         (env.host_string.replace('.', '_'),
                          timestamp),
                         pty=False)
    except SystemExit, e:

        logger.warn("Exception while executing task: %s", str(e))


@task
@parallel
def test_tcp_client(
    environment,
    server,
    config,
    endpoints,
    timestamp,
    osutils,
     floating_ip_map):
    print "TCP CLIENT Testing Code"
    print "ENDPOINTS:", endpoints
    try:
        for src_ep in endpoints:
            new_server = osutils.get_fixed_ip(server, floating_ip_map)
            if src_ep == env.host_string:
                if server != env.host_string:
		    sudo("iperf -c %s -t %s -p 6005 > tcptesttrafficclient-%s-%s-%s.txt 2>&1 &" %
                         (new_server,
                          config['traffic']['iperf_duration'],
                          env.host_string.replace('.', '_'),
                          new_server.replace('.', '_'),
                          timestamp),
                         pty=False)
    except SystemExit, e:
        logger.warn("Exception while executing task: %s", str(e))


def test_udp_server(environment, config, endpoints, timestamp):
    print "UDP SERVER Testing Code"
    print "ENDPOINTS:", endpoints

    try:
        for dest_ep in endpoints:
            if dest_ep == env.host_string:
                sudo("iperf3 -s -p 5010 -i 1 > udptesttrafficserver-%s-%s.txt 2>&1 &" %
                         (env.host_string.replace('.', '_'),
                          timestamp),
                         pty=False)
    except SystemExit, e:
        logger.warn("Exception while executing task: %s", str(e))


@task
@parallel
def test_udp_client(environment, server, config, endpoints, timestamp):
    print "UDP CLIENT Testing Code"
    print "ENDPOINTS:", endpoints

    try:
        for src_ep in endpoints:
            print "SOURCE EP........", src_ep
            print "SERVER...........", server
            if src_ep != env.host_string:
                sudo("iperf3 -c %s -u -t %s -p 5010 > udptesttrafficclient-%s-%s-%s.txt 2>&1 &" %
                         (server,
                          config['traffic']['iperf_duration'],
                          env.host_string.replace('.', '_'),
                          server.replace('.', '_'),
                          timestamp),
                         pty=False)
    except SystemExit, e:
        logger.warn("Exception while executing task: %s", str(e))


@task
def test_http(environment, contract, timestamp):
    print "HTTP testing code"


@task
def test_https(environment, contract, timestamp):
    print "HTTPS testing code"


@task
def test_SMTP(environment, contract, timestamp):
    print "SMTP testing code"


@task
def test_DNS(environment, contract, timestamp):
    print "DNS testing code"


@task
def test_FTP(environment, contract, timestamp):
    print "FTP testing code"


@task
def test_any(environment, contract, timestamp):
    print "ANY!! testing code"


def capture_output():
    pass


@task
@parallel
def stop_traffic(environment, endpoints, timestamp):
    with hide('running', 'stdout'):
        output = {'endpoints' : endpoints }

        try:
            ping_ps_stat = sudo("pgrep ping")
            if ping_ps_stat.return_code == 0:
                sudo("kill -SIGINT `pgrep ping`")

        # print "dest_eps are.....", endpoints['dest_eps']
            put("scripts/get_ping_statistics.py", "get_ping_statistics.py")
            out = run("python get_ping_statistics.py %s %s %s" % (endpoints['src_grp'], endpoints['dest_grp'], timestamp))

            out_dict = json.JSONDecoder().decode(out)

            output['test_result'] = out_dict
            print ">"*50
            print "Output as follows:"
            print output


            print "<"*50

            return output
        except SystemExit, e:
            output['test_result'] = None
            logger.warn("Exception while executing task: %s", str(e))
            return output

        except:
            output['test_result'] = None
            logger.warn("Exception while executing task")
            return output


@task
@parallel
def stop_iperf_traffic(environment, traffic_type, server, endpoints, timestamp):
    output = {'endpoints': endpoints}
    try:

        if server == '':
            try:
                print "Killing iperf on server"
                sudo("kill -SIGINT `pgrep iperf`")
            except SystemExit, e:
                logger.warn("Exception while executing task: %s", str(e))

#            print "server endpoint is.....", dest_ep

            return True
        else:

            try:
                print "Killing iperf on client"
                sudo("kill -SIGINT `pgrep iperf`")
            except SystemExit, e:
                logger.warn("Exception while executing task: %s", str(e))

#            print "client endpoint is.....", dest_ep

            if traffic_type == 'tcp':

                put("scripts/get_iperf_tcp_statistics.py",
                    "get_iperf_tcp_statistics.py")
                out = run("python get_iperf_tcp_statistics.py %s %s %s" %
                          (endpoints['src_grp'], endpoints['dest_grp'], timestamp))
            if traffic_type == 'udp':
                put("scripts/get_iperf_udp_statistics.py",
                    "get_iperf_udp_statistics.py")
                out = run("python get_iperf_udp_statistics.py %s" %
                          (timestamp))

            out_dict = json.JSONDecoder().decode(out)
            print "out is.......", out_dict
            output = {'src_tenant': endpoints['src_tenant'],
                     'dest_tenant': endpoints['dest_tenant'],
                     'test_result': out_dict}

            print "output......", output

            return output
    except SystemExit, e:
        output['test_result'] = None
        logger.warn("Exception while executing task: %s", str(e))
    except:
        output['test_result'] = None
        logger.warn("Exception while executing task")



def start_task(
    config,
    endpoints_list,
    action,
    osutils,
    floating_ip_map,
     testPrefix=None):

    timestamp = testPrefix
    if not testPrefix:
        timestamp = time.strftime("%Y-%m-%d-%H-%M-%S")

    output_table_data_list = []
    tcp_output_table_data_list = []
    udp_output_table_data_list = []
    if action == 'start':
        for endpoints in endpoints_list:
            if config['traffic']['backup_ptg_interface_up'] == 'True':
                setup_env(config, endpoints['src_eps'])
                backup_ptg_ip_info = execute(
                    activate_backup_interface, env, config)
                print backup_ptg_ip_info

            table_data = {}

            for contract in endpoints['contract']:

                print contract
                if contract['protocol'] == 'icmp':
                    setup_env(config, endpoints['src_eps'])
                    execute(create_test_results_directory, env)
                    execute(
                        test_ping, env, config, endpoints, contract, timestamp)

                if contract['protocol'] == 'tcp':
                    server_ip = [endpoints['src_eps'][0]]
                    setup_env(config, server_ip)
                    if contract['port'] == None:
                        out_ssh = (os.system("netstat -an | grep ':5005 '") + os.system("netstat -an | grep ':5010 '"))
                        print "OUT SSH SERVER value= ", out_ssh
                        if (out_ssh > 0):
                            execute(test_tcp_server, env, config, server_ip, timestamp)
                            setup_env(config, endpoints['dest_eps'])
                    execute(install_iperf, env)
                    server = server_ip[0]
                    if contract['port'] == None:
                        out_ssh = (os.system("netstat -an | grep ':5005 '") + os.system("netstat -an | grep ':5010 '"))
                        print "OUT SSH CLIENT Value= ", out_ssh
                        if (out_ssh > 0):
                            execute(test_tcp_client, env, server, config, endpoints['dest_eps'], timestamp, osutils, floating_ip_map)
#                if contract['protocol'] == 'udp':
#                    server_ip = [endpoints['src_eps'][0]]
#                    setup_env(config, server_ip)
#                    execute(create_test_results_directory, env)
#                    execute(install_iperf, env)
#                    if contract['port'] == None:
#                        out_ssh = (os.system("netstat -an | grep ':5005 '") + os.system("netstat -an | grep ':5010 '"))
#                        if (out_ssh > 0):
#                            execute(test_udp_server, env, config, server_ip, timestamp)
#                        setup_env(config, endpoints['dest_eps'])
#                    execute(install_iperf, env)
#                    server = server_ip[0]
#                    if contract['port'] == None:
#                        out_ssh = (os.system("netstat -an | grep ':5005 '") + os.system("netstat -an | grep ':5010 '"))
#                        if (out_ssh > 0):
#                            execute(test_udp_client, env, server, config, endpoints['dest_eps'], timestamp)
#                 if contract['protocol'] == 'udp'
#                     setup_env(config, endpoints['dest_eps'])
#                     install_iperf(env)
#                     out_ssh = (os.system("netstat -an | grep ':5005'") + os.system("netstat -an | grep ':5010'"))
#                     if (out_ssh > 0):
#                         execute(test_udp_server, env, config, endpoints['dest_eps'], timestamp)
#                     setup_env(config, endpoints['src_eps'])
#                     install_iperf(env)
#                     out_ssh = (os.system("netstat -an | grep ':5005'") + os.system("netstat -an | grep ':5010'"))
#                     if (out_ssh > 0):
#                         execute(test_udp_client, env, config, endpoints['src_eps'], timestamp)
    if action == 'stop':
        for endpoints in endpoints_list:
            for contract in endpoints['contract']:
                if contract['protocol'] == 'icmp':
                    endpoint_result = {}
                    setup_env(config, endpoints['src_eps'])
                    table_data = execute(stop_traffic, env, endpoints, timestamp)
                    endpoint_id = endpoints['src_grp'] + '_to_' + endpoints['dest_grp']
                    
                    endpoint_result[endpoint_id] = table_data
                    output_table_data_list.append(endpoint_result)
                    
                if contract['protocol'] == 'tcp':
                    endpoint_result = {}
                    server_ip = [endpoints['src_eps'][0]]
                    setup_env(config, endpoints['src_eps'])
                    print "endpoints...", endpoints['src_eps']
                    server = ''
                    execute(stop_iperf_traffic, env, 'tcp', server, endpoints, timestamp)
                    setup_env(config, endpoints['dest_eps'])
                    server = server_ip[0]
                    if server in env['hosts']:
                        env['hosts'].remove(server)
                        table_data = execute(stop_iperf_traffic, env, 'tcp', server, endpoints, timestamp)
                    if (table_data not in tcp_output_table_data_list):
                        tcp_output_table_data_list.append(table_data)
 #               if contract['protocol'] == 'udp':
 #                   server_ip = [endpoints['src_eps'][0]]
 #                   setup_env(config, endpoints['src_eps'])
 #                   server = ''
 #                   execute(stop_iperf_traffic, env, 'udp', server, endpoints, timestamp)
 #                   setup_env(config, endpoints['dest_eps'])
 #                   server = server_ip[0]
 #                   table_data = execute(stop_iperf_traffic, env, 'udp', server, endpoints, timestamp)
 #                   udp_output_table_data_list.append(table_data)


    if output_table_data_list:
#        return 0
        pretty_table_content(config, output_table_data_list)
#    if tcp_output_table_data_list:
#        print "TCP Traffic Results"
#        iperf_tcp_pretty_table_content(config, tcp_output_table_data_list)
#        print "\n"
#    if udp_output_table_data_list:
#        print "UDP Traffic Results"
#        iperf_udp_pretty_table_content(config, udp_output_table_data_list)
#        print "\n"

