import json
import os
import re
import sys


src_grp = sys.argv[1]
dest_grp = sys.argv[2]
fileid = sys.argv[3]
filedir = os.getcwd()


def get_list_of_filenames():
    file_list = []
    p = re.compile(ur'tcptesttrafficclient*%s.*%s.*%s' %(src_grp, dest_grp, fileid))
    for file in os.listdir(filedir):
        if re.search(p, file):
            file_list.append(file)
    return file_list


def process_files(file_list):
    out = {}
    for file in file_list:
        out[file] = get_test_results(file)
    return out


def get_test_results(file):
    """
    For a given test output file, return a tuple of the following format
    (bandwidth_loss dict wth keys interval_time, transferred, bandwidth, 
     jitter, loss_datagram, total_datagram, loss_percent)
    """
        
    bandwidth_stats = \
        {'interval_time': '',   # NOQA
         'transferred': '',   # NOQA
         'bandwidth': ''}   # NOQA
         #'retr': ''}   # NOQA
    reportflag = False
    f = open(file, 'r')
    for line in f:
        #if "--" in line:
        #    reportflag = True
        if "[ ID]" in line:
            #print "inside for loop", reportflag
            report = f.next()
            report_data = report.split(']')[1].split('  ')
            # also want packets transmitted, packets received, % packet loss
            #if str(report_data[2]) == 'sec':
            #interval_time = str(report_data[1]) + " " + str(report_data[2])
            interval_time = str(report_data[1])
            transferred = str(report_data[2])
            bandwidth = str(report_data[3]).split('\n')[0]
                #if report_data[5] == '':
                #    retr = str(report_data[5]) + str(report_data[6])   # NOQA
                #else:
                #    retr = str(report_data[5])
            #else:
            #    interval_time = str(report_data[1])
            #    transferred = str(report_data[2])
            #    bandwidth = str(report_data[3])
            #    if report_data[4] == '':
            #        retr = str(report_data[4]) + str(report_data[5])   # NOQA
            #    else:
            #        retr = str(report_data[4])
   
            bandwidth_stats = \
                {'interval_time': interval_time,   # NOQA
                 'transferred': transferred,   # NOQA
                 'bandwidth': bandwidth}   # NOQA
                # 'retr': retr}   # NOQA
    
    test_results = {'bandwidth_stats': bandwidth_stats}
    #print "test_results.....", test_results



    return test_results


def main():
    file_list = get_list_of_filenames()
    script_output = process_files(file_list)
    json_output = json.JSONEncoder().encode(script_output)
    # sample output
    # {'test.txt': ({'packet_loss': '0%'},
    #               {'rtt_min': '4.3', 'rtt_avg': '5.5', 'rtt_max': '6.3'})}
    print json_output
    #return  script_ouput

if __name__ == '__main__':
    main()
