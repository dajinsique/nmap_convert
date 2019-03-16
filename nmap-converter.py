#!/usr/bin/env python
#
# origin https://github.com/mrschyte/nmap-converter
# 
# edit by dajinsique 2019-3-16

from libnmap.parser import NmapParser, NmapParserException
from xlsxwriter import Workbook
from datetime import datetime

import os.path

def generate_summary(workbook, sheet, report):
    summary_header = ["Scan", "Command", "Version", "Scan Type", "Started", "Completed", "Hosts Total", "Hosts Up", "Hosts Down"]
    summary_header1 = ["Scan", "Command", "Version", "Scan Type", "Started", "Completed", "Hosts Total", "Hosts Up", "Hosts Down", "Diff", "Elapsed","Endtimestr","Hosts","Id","Save","Summary"]
    summary_body = {"Scan": lambda report: report.basename,
                    "Command": lambda report: report.commandline,
                    "Version": lambda report: report.version,
                    "Scan Type": lambda report: report.scan_type,
                    "Started": lambda report: datetime.utcfromtimestamp(report.started).strftime("%Y-%m-%d %H:%M:%S (UTC)"),
                    "Completed": lambda report: datetime.utcfromtimestamp(report.endtime).strftime("%Y-%m-%d %H:%M:%S (UTC)"),
                    "Hosts Total": lambda report: report.hosts_total,
                    "Hosts Up": lambda report: report.hosts_up,
                    "Hosts Down": lambda report: report.hosts_down,
                    "Diff":lambda report: "Not implemented",
                    "Elapsed":lambda report: report.elapsed,
                    "Endtimestr":lambda report: report.endtimestr,
                    "Hosts":lambda report: hosts_to_str(report.hosts),
                    "Id":lambda report: report.id,
                    #"Save":lambda report: report.save,
                    "Save":lambda report: "Not implemented",
                    "Summary":lambda report: report.summary
                    }
    #for idx, item in enumerate(summary_header1):
    #    print ("%s: %s"%(item, summary_body[item](report)))
    for idx, item in enumerate(summary_header1):
        sheet.write(0, idx, item, workbook.myformats["fmt_bold"])
        for idx, item in enumerate(summary_header1):
            #print("+++++++++++++++%s+++++++++++++++"%(item))
            sheet.write(sheet.lastrow + 1, idx, summary_body[item](report))

    sheet.lastrow = sheet.lastrow + 1

def hosts_to_str(hosts):
    return "\n".join([str(h) for h in hosts])


def generate_hosts(workbook, sheet, report):
    sheet.autofilter("A1:E1")
    sheet.freeze_panes(1, 0)

    hosts_header = ["IP", "MAC", "Host", "Status", "Lastboot", "Hops", "UPtime(s)","UPtime","Starttime", "Endtime", "Services Num",  "OS", "IP sequence", "IPv4", "IPv6", "Get_open_ports", "TCP sequence", "Services", "Scripts_results", "Extraports_reasons","Extraports_state","Get_dict",]
    hosts_body = {"Host": lambda host: next(iter(host.hostnames), ""),
                  "IP": lambda host: host.address,
                  "MAC":lambda host:host.mac,
                  "Status": lambda host: host.status,
                  "Lastboot": lambda host:host.lastboot,
                  "Hops":lambda host:host.distance,
                  "UPtime(s)":lambda host:host.uptime,
                  "UPtime":lambda host:seconds_to_time(host.uptime),
                  "Starttime": lambda host:datetime.utcfromtimestamp(int(host.starttime)).strftime("%Y-%m-%d %H:%M:%S"),
                  "Endtime": lambda host:datetime.utcfromtimestamp(int(host.endtime)).strftime("%Y-%m-%d %H:%M:%S"),
                  "Services Num": lambda host: len(host.services),
                  "OS": lambda host: os_class_string(host.os_class_probabilities()),
                  "IP sequence":lambda host:host.ipsequence,
                  "IPv4": lambda host:host.ipv4,
                  "IPv6": lambda host:host.ipv6,
                  "Get_open_ports":lambda host:open_ports_to_str(host.get_open_ports()),
                  "Services":lambda host:services_to_str(host.services),
                  #"Services":lambda host:"Not implemented",
                  "TCP sequence":lambda host:host.tcpsequence,
                  "Scripts_results":lambda host:scripts_results_to_str(host.scripts_results),
                  "Extraports_reasons":lambda host: extraports_reasons_2_str(host.extraports_reasons),
                  "Extraports_state":lambda host:extraports_state_2_str(host.extraports_state),
                  "Get_dict":lambda host:dict_to_str(host.get_dict())
                  }
    for idx, item in enumerate(hosts_header):
        sheet.write(0, idx, item, workbook.myformats["fmt_bold"])
    row = sheet.lastrow
    for host in report.hosts:
        #print(dir(host))
        for idx, item in enumerate(hosts_header):
            #print("*********%s*****************"%(item))
            sheet.write(row + 1, idx, hosts_body[item](host))
        row += 1
    sheet.lastrow = row


def seconds_to_time(seconds):
    time = ""
    h = 0
    d = 0
    m, s = divmod(seconds, 60)
    time = str(s)+"s"
    if m>= 60:
        h, m = divmod(m, 60)
        time = str(m)+"min "+time
        if h>24:
            d, h = divmod(h, 60)
            time = str(d)+"day(s) "+str(h)+"h "+time
        else:
            time = str(h)+"h "+time
    else:
        time = str(m)+"min "+time
    return time

def timestamp_datetime(value):
    format = '%Y-%m-%d %H:%M:%S'
    value = time.localtime(value)
    dt = time.strftime(format, value)
    return dt

def os_class_string(os_class_array):
    return " | ".join(["{0} ({1}%)".format(os_string(osc), osc.accuracy) for osc in os_class_array])

def os_string(os_class):
    rval = "{0}, {1}".format(os_class.vendor, os_class.osfamily)
    if len(os_class.osgen):
        rval += "({0})".format(os_class.osgen)
    return rval

def open_ports_to_str(open_ports_list):
    return "\n".join([str(p) for p in open_ports_list])

def services_to_str(services):
    return "\n".join([str(s)for s in services])

def scripts_results_to_str(scripts_results):
    results_str=""
    for r in scripts_results:
        for key, value in r.items():
            #results_str.append("{0}: {1}".format(key, value))
            results_str = results_str + "{0}: {1}\n".format(key, value)
        results_str = results_str + "-------------------\n"
    #return  "\n".join(results_str)
    return results_str

def extraports_reasons_2_str(extraports_reasons):
    return "\n".join([str(er) for er in extraports_reasons])

def extraports_state_2_str(extraports_state):
    return "\n".join([str(es) for es in extraports_state])

def dict_to_str(host_dict):
    return "\n".join(["{0}: {1}".format(str(key),str(key)) for key, value in host_dict.items()])



def generate_results(workbook, sheet, report):
    sheet.autofilter("A1:N1")
    sheet.freeze_panes(1, 0)

    sheet.data_validation("N2:N$1048576", {"validate": "list",
                                           "source": ["Y", "N", "N/A"]})

    results_header = ["IP", "MAC", "Host", "Name", "Port", "Protocol", "Status", "Service", "Service_dict", "Servicefp", "Tunnel", "Method", "Confidence", "Reason", "Reason_IP", "Reason_ttl","Product", "Version", "Extra", "Flagged", "Notes", "Owner", "Banner", "CPElist", "Get_dict", "ID", "Scripts_results"]
    results_body = {
                    "IP": lambda host, service: host.address,
                    "MAC":lambda host,service: host.mac,
                    "Host": lambda host, service: next(iter(host.hostnames), ""),
                    "Name": lambda host, service: hostnames_2_str(host.hostnames),
                    "Port": lambda host, service: service.port,
                    "Protocol": lambda host, service: service.protocol,
                    "Status": lambda host, service: service.state,
                    "Service": lambda host, service: service.service,
                    "Service_dict": lambda host, service: dict_to_str(service.service_dict),
                    "Servicefp":lambda host, service: service.servicefp,
                    "Tunnel": lambda host, service: service.tunnel,
                    "Method": lambda host, service: service.service_dict.get("method", ""),
                    "Confidence": lambda host, service: float(service.service_dict.get("conf", "0")) / 10,
                    "Reason": lambda host, service: service.reason,
                    "Reason_IP": lambda host, service: service.reason_ip,
                    "Reason_ttl":lambda host, service: service.reason_ttl,
                    "Product": lambda host, service: service.service_dict.get("product", ""),
                    "Version": lambda host, service: service.service_dict.get("version", ""),
                    "Extra": lambda host, service: service.service_dict.get("extrainfo", ""),
                    "Flagged": lambda host, service: "N/A",
                    "Notes": lambda host, service: "",
                    "Banner":lambda host,service: service.banner,
                    "CPElist": lambda host, service: cpelist_to_str(service.cpelist),
                    "Get_dict": lambda host, service: dict_to_str(service.get_dict()),
                    "ID": lambda host, service: service.id,
                    "Owner": lambda host, service: service.owner,
                    "Scripts_results":lambda host, service:scripts_results_to_str(service.scripts_results)
                    }

    results_format = {"Confidence": workbook.myformats["fmt_conf"]}

    print("[+] Processing {}".format(report.summary))
    for idx, item in enumerate(results_header):
        sheet.write(0, idx, item, workbook.myformats["fmt_bold"])

    row = sheet.lastrow
    for host in report.hosts:
        print("[+] Processing {}".format(host))
        for service in host.services:
            for idx, item in enumerate(results_header):
                #print("^^^^^^^^^^^^ %s ^^^^^^^^^^^^^^^"%(item))
                sheet.write(row + 1, idx, results_body[item](host, service), results_format.get(item, None))
            row += 1

    sheet.lastrow = row

def cpelist_to_str(cpelist):
    return "\n".join([str(cpe) for cpe in cpelist])

def hostnames_2_str(hostnameslist):
    return "\n".join([str(hostname) for hostname in hostnameslist]) 

def setup_workbook_formats(workbook):
    formats = {"fmt_bold": workbook.add_format({"bold": True}),
               "fmt_conf": workbook.add_format()}

    formats["fmt_conf"].set_num_format("0%")
    return formats


def main(reports, workbook):
    sheets = {"Summary": generate_summary,
              "Hosts": generate_hosts,
              "Results": generate_results}

    workbook.myformats = setup_workbook_formats(workbook)

    for sheet_name, sheet_func in sheets.items():
        sheet = workbook.add_worksheet(sheet_name)
        sheet.lastrow = 0
        for report in reports:
            #print (dir([report]))
            sheet_func(workbook, sheet, report)
    workbook.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", metavar="XLS", help="path to xlsx output")
    parser.add_argument("reports", metavar="XML", nargs="+", help="path to nmap xml report")
    args = parser.parse_args()

    if args.output == None:
        parser.error("Output must be specified")

    reports = []
    for report in args.reports:
        try:
            parsed = NmapParser.parse_fromfile(report)
        except NmapParserException as ex:
            parsed = NmapParser.parse_fromfile(report, incomplete=True)
        
        parsed.basename = os.path.basename(report)
        reports.append(parsed)

    workbook = Workbook(args.output)
    main(reports, workbook)