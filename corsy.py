#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import argparse

from core.tests import active_tests
from core.utils import host, prompt, format_result, create_url_list
from core.colors import bad, end, red, run, good, grey, green, white, yellow


try:
    import concurrent.futures
    from urllib.parse import urlparse
except ImportError:
    print(" %s corsy needs Python > 3.4 to run." % bad)
    quit()

parser = argparse.ArgumentParser()
parser.add_argument("-u", help="target url", dest="target")
parser.add_argument("-o", help="json output file", dest="json_file")
parser.add_argument("-i", help="input file urls/subdomains", dest="inp_file")
parser.add_argument("-t", help="thread count", dest="threads", type=int, default=2)
parser.add_argument("-d", help="request delay", dest="delay", type=float, default=0)
parser.add_argument("-q", help="don't print help tips", dest="quiet", action="store_true")
parser.add_argument("--headers", help="add headers", dest="header_dict", nargs="?", const=True)
args = parser.parse_args()

delay = args.delay
quiet = args.quiet
target = args.target
threads = args.threads
inp_file = args.inp_file
json_file = args.json_file
header_dict = args.header_dict

if type(header_dict) == bool:
    header_dict = extractHeaders(prompt())
elif type(header_dict) == str:
    header_dict = extractHeaders(header_dict)
else:
    header_dict = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip",
        "DNT": "1",
        "Connection": "close",
    }

urls = create_url_list(target, inp_file)


def cors(target, header_dict, delay):
    url = target
    root = host(url)
    parsed = urlparse(url)
    # netloc = parsed.netloc
    scheme = parsed.scheme
    # url = scheme + "://" + netloc
    return active_tests(url, root, scheme, header_dict, delay)


if urls:
    if len(urls) > 1:
        print(" %s Estimated scan time: %i secs" % (run, round(len(urls) * 1.75)))
    results = []
    threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    futures = (threadpool.submit(cors, url, header_dict, delay) for url in urls)
    for each in concurrent.futures.as_completed(futures):
        result = each.result()
        if result:
            for sub_result in result:
                results.append(sub_result)
                for i in sub_result:
                    print(" %s %s" % (good, i))
                    print("   %s-%s Class: %s" % (yellow, end, sub_result[i]["class"]))
                    if not quiet:
                        print("   %s-%s Description: %s" % (yellow, end, sub_result[i]["description"]))
                        print("   %s-%s Severity: %s" % (yellow, end, sub_result[i]["severity"]))
                        print("   %s-%s Exploitation: %s" % (yellow, end, sub_result[i]["exploitation"]))
                    print("   %s-%s ACAO Header: %s" % (yellow, end, sub_result[i]["acao header"]))
                    print("   %s-%s ACAC Header: %s\n" % (yellow, end, sub_result[i]["acac header"]))

    if results:
        if json_file:
            with open(json_file, "w+") as file:
                json.dump(results, file, indent=2)
    else:
        print(" %s No misconfigurations found." % bad)
else:
    print(" %s No valid URLs to test." % bad)
