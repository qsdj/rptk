'''

Registry Persistence Toolkit (RPTK) v1.0

License Information:

Copyright 2017 | Kyle Poppenwimer | @kpoppenwimer

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

'''

import argparse
import os
import sys
from Registry import Registry
import datetime
import re
import base64

sys.stdout.write('\n')
sys.stdout.write('#############################################')
sys.stdout.write('\n')
sys.stdout.write('                  RPTK v1.0                  ')
sys.stdout.write('\n')
sys.stdout.write('#############################################')
sys.stdout.write('\n')

argparser = argparse.ArgumentParser()

argparser.add_argument('-d', '--dir', dest='dir_path', type=str, action='store', default=None, required=True, help='Directory path to registry files', metavar='')
argparser.add_argument('-o', '--output', dest='output_dir', type=str, action='store', default=None, required=True, help='Directory path to log output directory', metavar='')
argparser.add_argument('-w', '--whitelist', dest='whitelist_path', type=str, action='store', default=None, required=True, help='Directory path to rptk_whitelist text file', metavar='')
argparser.add_argument('-i', '--ioc', dest='iocs_path', type=str, action='store', default=None, required=True, help='Directory path to rptk_iocs text file', metavar='')

args = argparser.parse_args()

#Reads rptk_whitelist.txt file into a list
wlist_path = args.whitelist_path
os.chdir(wlist_path)
rptk_whitelist = []

if os.path.isfile('rptk_whitelist.txt'):
    open_software = open('rptk_whitelist.txt', "r")
    soft_lines = open_software.readlines()
    for line in soft_lines:
        rptk_whitelist.append(line.strip('\r\n'))


#Reads rptk_iocs.txt file into a list
iocs_path = args.iocs_path
os.chdir(iocs_path)
rptk_iocs = []

if os.path.isfile('rptk_iocs.txt'):
    open_iocs = open('rptk_iocs.txt', "r")
    iocs_lines = open_iocs.readlines()
    for line in iocs_lines:
        rptk_iocs.append(line.strip('\r\n').lower())

dir_path = args.dir_path
os.chdir(dir_path)
output_dir = args.output_dir

b64_search = re.compile('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})')

#Global Hive Function

def parse_recursive(key, f):
    f(key)
    for subkey in key.subkeys():
        parse_recursive(subkey, f)

#SOFTWARE Hive Functions

def software_key_value(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

            x = key_path.split('}')[1]
            path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

            path_tracker = []

            for item in rptk_whitelist:
                path_tracker.append(item)

            if path in rptk_whitelist:
                software_output.write('\n')
                software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')
                path_tracker.remove(path)

            if path not in rptk_whitelist:
                for ioc in rptk_iocs:
                    if str(ioc) in str(value.value()).lower():
                        software_output.write('\n')
                        software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                        software_output.write('\n')
                        path_tracker.append(path)

            path_tracker2 = []

            for item in rptk_whitelist:
                path_tracker2.append(item)

            for item in path_tracker:
                path_tracker2.append(item)

            if path not in path_tracker2:
                b64_list = []
                b64_list.append(path.split('\\')[-1])

                for item in b64_list:
                    search_string = ''.join(item.split())
                    search_results = b64_search.findall(str(search_string))
                    result_string = str(search_results)

                    if len(result_string) > 10:
                        if '.' in item:
                            break;

                        else:
                            software_output.write('\n')
                            software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                            software_output.write('\n')
                            path_tracker2.append(path)

            path_tracker3 = []

            for item in path_tracker2:
                path_tracker3.append(item)

            if path not in path_tracker3:
                software_output.write('\n')
                software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def CLSID_value_type_lookup(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:

        for value in [v for v in key.values()

            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

            p = key_path.split('}')[1]
            path = str(p) + '\\' + str(value.name()) + '\\' + str(value.value())

            path_tracker = []

            for item in rptk_whitelist:
                path_tracker.append(item)

            if path in rptk_whitelist:
                software_output.write('\n')
                software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')
                path_tracker.remove(path)

            if path not in rptk_whitelist:
                for ioc in rptk_iocs:
                    if str(ioc) in str(value.value()).lower():
                        software_output.write('\n')
                        software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                        software_output.write('\n')
                        path_tracker.append(path)

            path_tracker2 = []

            for item in rptk_whitelist:
                path_tracker2.append(item)

            for item in path_tracker:
                path_tracker2.append(item)

            if path not in path_tracker2:
                b64_list = []
                b64_list.append(path.split('\\')[-1])

                for item in b64_list:
                    search_string = ''.join(item.split())
                    search_results = b64_search.findall(str(search_string))
                    result_string = str(search_results)

                    if len(result_string) > 10:
                        if '.' in item:
                            break;

                        else:
                            software_output.write('\n')
                            software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                            software_output.write('\n')
                            path_tracker2.append(path)

            path_tracker3 = []

            for item in path_tracker2:
                path_tracker3.append(item)

            if path not in path_tracker3:
                software_output.write('\n')
                software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')

            x = '%s' % value.value()
            clsid_list = [str(x)]

            for x in clsid_list:

                try:

                    clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write('\t\tWHITELISTED:\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write( '\t\tSUSPICIOUS IOC:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')

                    clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value2.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write('\t\tWHITELISTED:\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(
                                value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')
                except:
                    pass;

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


def CLSID_value_name_lookup_2(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:

        for value in [v for v in key.values()

            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

            p = key_path.split('}')[1]
            path = str(p) + '\\' + str(value.name()) + '\\' + str(value.value())

            path_tracker = []

            for item in rptk_whitelist:
                path_tracker.append(item)

            if path in rptk_whitelist:
                software_output.write('\n')
                software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')
                path_tracker.remove(path)

            if path not in rptk_whitelist:
                for ioc in rptk_iocs:
                    if str(ioc) in str(value.value()).lower():
                        software_output.write('\n')
                        software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                        software_output.write('\n')
                        path_tracker.append(path)

            path_tracker2 = []

            for item in rptk_whitelist:
                path_tracker2.append(item)

            for item in path_tracker:
                path_tracker2.append(item)

            if path not in path_tracker2:
                b64_list = []
                b64_list.append(path.split('\\')[-1])

                for item in b64_list:
                    search_string = ''.join(item.split())
                    search_results = b64_search.findall(str(search_string))
                    result_string = str(search_results)

                    if len(result_string) > 10:
                        if '.' in item:
                            break;

                        else:
                            software_output.write('\n')
                            software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                            software_output.write('\n')
                            path_tracker2.append(path)

            path_tracker3 = []

            for item in path_tracker2:
                path_tracker3.append(item)

            if path not in path_tracker3:
                software_output.write('\n')
                software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')

            x = '%s' % value.name()
            clsid_list = [str(x)]

            for x in clsid_list:

                try:

                    clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write('\t\tWHITELISTED:\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write( '\t\tSUSPICIOUS IOC:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write( '\t\tREVIEW:\t\t\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')

                    clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value2.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write('\t\tWHITELISTED:\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(
                                value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')
                except:
                    pass;


    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def CLSID_value_type_lookup_3(key):
    key_path = key.path()
    clsid_list2 = [str(key_path.rsplit('\\', 1)[1])]

    software_output.write('\n')
    software_output.write('Key Path: ' + key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:

        for value in [v for v in key.values()

            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

            p = key_path.split('}')[1]
            path = str(p) + '\\' + str(value.name()) + '\\' + str(value.value())

            path_tracker = []

            for item in rptk_whitelist:
                path_tracker.append(item)

            if path in rptk_whitelist:
                software_output.write('\n')
                software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')
                path_tracker.remove(path)

            if path not in rptk_whitelist:
                for ioc in rptk_iocs:
                    if str(ioc) in str(value.value()).lower():
                        software_output.write('\n')
                        software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                        software_output.write('\n')
                        path_tracker.append(path)

            path_tracker2 = []

            for item in rptk_whitelist:
                path_tracker2.append(item)

            for item in path_tracker:
                path_tracker2.append(item)

            if path not in path_tracker2:
                b64_list = []
                b64_list.append(path.split('\\')[-1])

                for item in b64_list:
                    search_string = ''.join(item.split())
                    search_results = b64_search.findall(str(search_string))
                    result_string = str(search_results)

                    if len(result_string) > 10:
                        if '.' in item:
                            break;

                        else:
                            software_output.write('\n')
                            software_output.write('\t\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                            software_output.write('\n')
                            path_tracker2.append(path)

            path_tracker3 = []

            for item in path_tracker2:
                path_tracker3.append(item)

            if path not in path_tracker3:
                software_output.write('\n')
                software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')

            x = '%s' % value.value()
            clsid_list = [str(x)]

            for x in clsid_list:

                try:

                    clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write('\t\tWHITELISTED:\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write( '\t\tSUSPICIOUS IOC:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write( '\t\tREVIEW:\t\t\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')

                    clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value2.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write('\t\tWHITELISTED:\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(
                                value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')
                except:
                    pass;

            for x in clsid_list2:

                try:
                    clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path3 = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path3) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write( '\t\tWHITELISTED:\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path3) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path3) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path3) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path3) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write( '\t\tREVIEW:\t\t\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')

                    clsid_value = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path4 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path4) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write('\t\tWHITELISTED:\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path4) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path4) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path4) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path4) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')

                except:
                    pass;

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def CLSID_value_type_lookup_4(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:

        for value in [v for v in key.values()

            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

            p = key_path.split('}')[1]
            path = str(p) + '\\' + str(value.name()) + '\\' + str(value.value())

            path_tracker = []

            for item in rptk_whitelist:
                path_tracker.append(item)

            if path in rptk_whitelist:
                software_output.write('\n')
                software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')
                path_tracker.remove(path)

            if path not in rptk_whitelist:
                for ioc in rptk_iocs:
                    if str(ioc) in str(value.value()).lower():
                        software_output.write('\n')
                        software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                        software_output.write('\n')
                        path_tracker.append(path)

            path_tracker2 = []

            for item in rptk_whitelist:
                path_tracker2.append(item)

            for item in path_tracker:
                path_tracker2.append(item)

            if path not in path_tracker2:
                b64_list = []
                b64_list.append(path.split('\\')[-1])

                for item in b64_list:
                    search_string = ''.join(item.split())
                    search_results = b64_search.findall(str(search_string))
                    result_string = str(search_results)

                    if len(result_string) > 10:
                        if '.' in item:
                            break;

                        else:
                            software_output.write('\n')
                            software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                            software_output.write('\n')
                            path_tracker2.append(path)

            path_tracker3 = []

            for item in path_tracker2:
                path_tracker3.append(item)

            if path not in path_tracker3:
                software_output.write('\n')
                software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')

        for value in key.values():
            if value.name() == 'CLSID':

                x = '%s' % value.value()
                clsid_list = [str(x)]

                for x in clsid_list:
                    try:

                        clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                        clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                        for i, value in enumerate(clsid_value.values()):

                            path_tracker = []

                            for item in rptk_whitelist:
                                path_tracker.append(item)

                            if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                                software_output.write('\t\tWHITELISTED:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                software_output.write('\n')
                                path_tracker.remove(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                            if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                                for ioc in rptk_iocs:
                                    if str(ioc) in str(value.value()).lower():
                                        software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                        software_output.write('\n')
                                        path_tracker.append(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                            path_tracker2 = []

                            for item in rptk_whitelist:
                                path_tracker2.append(item)

                            for item in path_tracker:
                                path_tracker2.append(item)

                            if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                                software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('* - ' + value.name(), value.value()))
                                software_output.write('\n')

                        clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                        clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                        for i, value in enumerate(clsid_value2.values()):

                            path_tracker = []

                            for item in rptk_whitelist:
                                path_tracker.append(item)

                            if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                                software_output.write('\t\tWHITELISTED:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                software_output.write('\n')
                                path_tracker.remove(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                            if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                                for ioc in rptk_iocs:
                                    if str(ioc) in str(value.value()).lower():
                                        software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                        software_output.write('\n')
                                        path_tracker.append(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                            path_tracker2 = []

                            for item in rptk_whitelist:
                                path_tracker2.append(item)

                            for item in path_tracker:
                                path_tracker2.append(item)

                            if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                                software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('# - ' + value.name(), value.value()))
                                software_output.write('\n')
                    except:
                        pass;


    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def CLSID_key_name_lookup(key):

    key_path = key.path()
    clsid_list = [str(key_path.rsplit('\\', 1)[1])]

    software_output.write('\n')
    software_output.write(key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:

        for x in clsid_list:

            try:

                clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                for i, value in enumerate(clsid_value.values()):

                    path_tracker = []

                    for item in rptk_whitelist:
                        path_tracker.append(item)

                    if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                        software_output.write('\t\tWHITELISTED:\t{}: {}'.format('* - ' + value.name(), value.value()))
                        software_output.write('\n')
                        path_tracker.remove(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                    if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                        for ioc in rptk_iocs:
                            if str(ioc) in str(value.value()).lower():
                                software_output.write(
                                    '\t\tSUSPICIOUS IOC:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                software_output.write('\n')
                                path_tracker.append(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                    path_tracker2 = []

                    for item in rptk_whitelist:
                        path_tracker2.append(item)

                    for item in path_tracker:
                        path_tracker2.append(item)

                    if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                        software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('* - ' + value.name(), value.value()))
                        software_output.write('\n')

                clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                for i, value in enumerate(clsid_value2.values()):

                    path_tracker = []

                    for item in rptk_whitelist:
                        path_tracker.append(item)

                    if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                        software_output.write('\t\tWHITELISTED:\t{}: {}'.format('# - ' + value.name(), value.value()))
                        software_output.write('\n')
                        path_tracker.remove(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                    if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(
                            value.value()) not in rptk_whitelist:
                        for ioc in rptk_iocs:
                            if str(ioc) in str(value.value()).lower():
                                software_output.write(
                                    '\t\tSUSPICIOUS IOC:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                software_output.write('\n')
                                path_tracker.append(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                    path_tracker2 = []

                    for item in rptk_whitelist:
                        path_tracker2.append(item)

                    for item in path_tracker:
                        path_tracker2.append(item)

                    if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                        software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('# - ' + value.name(), value.value()))
                        software_output.write('\n')
            except:
                pass;

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


def SharedTaskScheduler(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + str(key_path))
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

            p = key_path.split('}')[1]
            path = str(p) + '\\' + str(value.name()) + '\\' + str(value.value())

            path_tracker = []

            for item in rptk_whitelist:
                path_tracker.append(item)

            if path in rptk_whitelist:
                software_output.write('\n')
                software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')
                path_tracker.remove(path)

            if path not in rptk_whitelist:
                for ioc in rptk_iocs:
                    if str(ioc) in str(value.value()).lower():
                        software_output.write('\n')
                        software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                        software_output.write('\n')
                        path_tracker.append(path)

            path_tracker2 = []

            for item in rptk_whitelist:
                path_tracker2.append(item)

            for item in path_tracker:
                path_tracker2.append(item)

            if path not in path_tracker2:
                b64_list = []
                b64_list.append(path.split('\\')[-1])

                for item in b64_list:
                    search_string = ''.join(item.split())
                    search_results = b64_search.findall(str(search_string))
                    result_string = str(search_results)

                    if len(result_string) > 10:
                        if '.' in item:
                            break;

                        else:
                            software_output.write('\n')
                            software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                            software_output.write('\n')
                            path_tracker2.append(path)

            path_tracker3 = []

            for item in path_tracker2:
                path_tracker3.append(item)

            if path not in path_tracker3:
                software_output.write('\n')
                software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                software_output.write('\n')

            x = '%s' % value.name()
            clsid_list = [str(x)]

            for x in clsid_list:
                try:

                    clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write('\t\tWHITELISTED:\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('* - ' + value.name(), value.value()))
                            software_output.write('\n')

                    clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value2.values()):

                        path_tracker = []

                        for item in rptk_whitelist:
                            path_tracker.append(item)

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                            software_output.write('\t\tWHITELISTED:\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.remove(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                            for ioc in rptk_iocs:
                                if str(ioc) in str(value.value()).lower():
                                    software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                    software_output.write('\n')
                                    path_tracker.append(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                        path_tracker2 = []

                        for item in rptk_whitelist:
                            path_tracker2.append(item)

                        for item in path_tracker:
                            path_tracker2.append(item)

                        if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                            software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('# - ' + value.name(), value.value()))
                            software_output.write('\n')
                except:
                    pass;

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def winlogon_values(key):
    key_path = key.path()

    try:

        for value in key.values():

            if value.name() == 'Userinit':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() =='VMApplet':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() =='Shell':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() =='AppSetup':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() =='GinaDLL':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\t\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() =='LsaStart':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\t\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() =='SaveDumpStart':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\t\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() == 'ServiceControllerStart':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\t\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() == 'System':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\t\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() == 'Taskman':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\t\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

            elif value.name() == 'UIHost':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\t\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def notify_dllname_value(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + str(key_path))
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:
        for value in key.values():
            if value.name() == 'DLLName':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def stub_path_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'StubPath':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('Key Path: ' + key.path())
                    software_output.write('\n')
                    software_output.write('Last Write Time: ' + str(key.timestamp()))
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('Key Path: ' + key.path())
                            software_output.write('\n')
                            software_output.write('Last Write Time: ' + str(key.timestamp()))
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('Key Path: ' + key.path())
                                software_output.write('\n')
                                software_output.write('Last Write Time: ' + str(key.timestamp()))
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('Key Path: ' + key.path())
                    software_output.write('\n')
                    software_output.write('Last Write Time: ' + str(key.timestamp()))
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def appinit_dlls_value(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))

    try:
        for value in key.values():
            if value.name() == 'AppInit_DLLs':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def IconServiceLib_value(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + str(key_path))
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:
        for value in key.values():
            if value.name() == 'IconServiceLib':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def scripts_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'Scripts':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


def cmdar_key_value(key):
    key_path = key.path()
    software_output.write('\n')
    software_output.write('Key Path: ' + key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:
        for value in key.values():
            if value.name() == 'AutoRun':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
        else:
            software_output.write('\n')
            software_output.write('\tAutoRun Value Not Found')
            software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def common_startup_value(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))

    try:
        for value in key.values():
            if value.name() == 'Common Startup':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def IETB(key):
    key_path = key.path()

    software_output.write('\n')
    software_output.write('Key Path: ' + key.path())
    software_output.write('\n')
    software_output.write('Last Write Time: ' + str(key.timestamp()))
    software_output.write('\n')

    try:

        for value in [v for v in key.values()

            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegBin]:

                p = key_path.split('}')[1]
                path = str(p) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

                x = '%s' % value.name()
                clsid_list = [str(x)]

                for x in clsid_list:

                    try:

                        clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                        clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                        for i, value in enumerate(clsid_value.values()):

                            path_tracker = []

                            for item in rptk_whitelist:
                                path_tracker.append(item)

                            if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                                software_output.write('\t\tWHITELISTED:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                software_output.write('\n')
                                path_tracker.remove(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                            if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                                for ioc in rptk_iocs:
                                    if str(ioc) in str(value.value()).lower():
                                        software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('* - ' + value.name(), value.value()))
                                        software_output.write('\n')
                                        path_tracker.append(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))

                            path_tracker2 = []

                            for item in rptk_whitelist:
                                path_tracker2.append(item)

                            for item in path_tracker:
                                path_tracker2.append(item)

                            if str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                                software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('* - ' + value.name(), value.value()))
                                software_output.write('\n')

                        clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                        clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                        for i, value in enumerate(clsid_value2.values()):

                            path_tracker = []

                            for item in rptk_whitelist:
                                path_tracker.append(item)

                            if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) in rptk_whitelist:
                                software_output.write('\t\tWHITELISTED:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                software_output.write('\n')
                                path_tracker.remove(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                            if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in rptk_whitelist:
                                for ioc in rptk_iocs:
                                    if str(ioc) in str(value.value()).lower():
                                        software_output.write('\t\tSUSPICIOUS IOC:\t{}: {}'.format('# - ' + value.name(), value.value()))
                                        software_output.write('\n')
                                        path_tracker.append(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))

                            path_tracker2 = []

                            for item in rptk_whitelist:
                                path_tracker2.append(item)

                            for item in path_tracker:
                                path_tracker2.append(item)

                            if str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()) not in path_tracker2:
                                software_output.write('\t\tREVIEW:\t\t\t{}: {}'.format('# - ' + value.name(), value.value()))
                                software_output.write('\n')
                    except:
                        pass;

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

def IFEO(key):

    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'Debugger':

                p = key_path.split('}')[1]
                path = str(p) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    software_output.write('\n')
                    software_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            software_output.write('\n')
                            software_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            software_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                software_output.write('\n')
                                software_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                software_output.write('\n')
                                software_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                software_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    software_output.write('\n')
                    software_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    software_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write(key_path)
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

start_time = datetime.datetime.now()
sys.stdout.write('\n')
sys.stdout.write('Processing Started: ' + str(start_time).split(".")[0])
sys.stdout.write('\n')
sys.stdout.write('\n')
sys.stdout.write('Processing Software Hive')
sys.stdout.write('\n')


if os.path.isfile('SOFTWARE'):
    open_software = open('SOFTWARE', "rb")
    reg_software = Registry.Registry(open_software)
    software_path = os.path.join(output_dir, 'software_persistence.txt')
    software_output = open(software_path, 'a+')

    software_output.write('##############################################################################################################################################################')
    software_output.write('\n')
    software_output.write('\n')
    software_output.write('Registry Persistence Toolkit (RPTK) v1.0')
    software_output.write('\n')
    software_output.write('@kpoppenwimer')
    software_output.write('\n')
    software_output.write('\n')
    software_output.write('##############################################################################################################################################################')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Run'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\RunOnce'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\RunOnceEx'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\RunServices'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\RunServicesOnce'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\(Userinit)(Shell)(VMApplet)(AppSetup)(GinaDLL)(LsaStart)(SaveDumpStart)(System)(Taskman)(UIHost)')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Winlogon'), winlogon_values)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*\(DLLName)')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify'), notify_dllname_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Active Setup\\Installed Components'), stub_path_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Active Setup\\Installed Components'), stub_path_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad\*')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\\'), CLSID_value_type_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\tRegistry Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad\*')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\\'), CLSID_value_type_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\tRegistry Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\(AppInit_DLLs)')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Windows'), appinit_dlls_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\(AppInit_DLLs)')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), appinit_dlls_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\(IconServiceLib)')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Windows'), IconServiceLib_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Policies\\Microsoft\\Windows\\System\\Scripts'), scripts_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\'), CLSID_key_name_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\t Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\'), CLSID_key_name_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\t Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler\(*)')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler\\'), SharedTaskScheduler)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\tRegistry Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler\(*)')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler\\'), SharedTaskScheduler)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\tRegistry Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Command Processor\(Autorun)')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Command Processor'), cmdar_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Command Processor\(Autorun)')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Command Processor'), cmdar_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\(Common Startup)')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders'), common_startup_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('Key Not Found')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\(Common Startup)')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders'), common_startup_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\\batfile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\batfile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\cmdfile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\cmdfile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\comfile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\comfile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\exefile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\exefile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\htafile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\htafile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\htmlfile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\htmlfile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\htmlfile\shell\opennew\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\htmlfile\\shell\\opennew\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\https\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\https\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\internetshortcut\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\internetshortcut\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\jsefile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\jsefile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\piffile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\piffile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\\regfile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\regfile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\srcfile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\srcfile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\\txtfile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\txtfile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\\vbsfile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\vbsfile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()


    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\wsffile\shell\open\command\*')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\wsffile\\shell\\open\\command'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\*\ShellEx\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\*\\ShellEx\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\*\ShellEx\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\*\\ShellEx\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\*\ShellEx\PropertySheetHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\*\\ShellEx\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\*\ShellEx\PropertySheetHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\*\\ShellEx\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\AllFileSystemObjects\\ShellEx\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\AllFileSystemObjects\\ShellEx\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\AllFileSystemObjects\ShellEx\DragDropHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\AllFileSystemObjects\\ShellEx\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\AllFileSystemObjects\ShellEx\DragDropHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\AllFileSystemObjects\\ShellEx\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('SOFTWARE\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\AllFileSystemObjects\\ShellEx\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('SOFTWARE\Wow6432Node\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\AllFileSystemObjects\\ShellEx\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\CLSID\{083863F1-70DE-11D0-BD40-00A0C911CE86\Instance\*')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\CLSID\\{083863F1-70DE-11D0-BD40-00A0C911CE86}\\Instance'), CLSID_value_type_lookup_4)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance}')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\CLSID\\{7ED96837-96F0-4812-B211-F13C24117ED3}\\Instance'), CLSID_value_type_lookup_4)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance}')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\CLSID\\{AC757296-3522-4E11-9862-C17BE5A1767E}\\Instance'), CLSID_value_type_lookup_4)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\CLSID\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\Instance}')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\CLSID\\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\\Instance'), CLSID_value_type_lookup_4)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\Background\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Directory\Background\shellex\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\Background\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Directory\shellex\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Directory\shellex\CopyHookHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\shellex\\CopyHookHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Directory\shellex\CopyHookHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\shellex\\CopyHookHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Directory\shellex\DragDropHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\shellex\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Directory\shellex\DragDropHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\shellex\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Directory\shellex\PropertySheetHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Drive\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Drive\shellex\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Drive\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Drive\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Folder\shellex\ColumnHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\ColumnHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Folder\shellex\ColumnHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\ColumnHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Folder\shellex\ContextMenuHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Folder\shellex\DragDropHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Folder\shellex\DragDropHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Folder\shellex\ExtShellFolderViews')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\ExtShellFolderViews'), CLSID_value_type_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Folder\shellex\ExtShellFolderViews')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\ExtShellFolderViews'), CLSID_value_type_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Folder\shellex\PropertySheetHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Classes\Folder\shellex\PropertySheetHandlers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\PROTOCOLS\Filter')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\PROTOCOLS\\Filter'), CLSID_value_type_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\PROTOCOLS\Handler')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\PROTOCOLS\\Handler'), CLSID_value_type_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Drivers32'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\Wow6432Node\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers'), CLSID_value_type_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers'), CLSID_value_type_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjects'), CLSID_key_name_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjects'), CLSID_key_name_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Internet Explorer\\Extensions'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Internet Explorer\\Extensions'), software_key_value)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Internet Explorer\Toolbar')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Internet Explorer\\Toolbar'), IETB)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Toolbar')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar'), IETB)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\(Debugger)')
    software_output.write('\n')
    software_output.write('NOTE: Entries will only be present if a "Debugger" value was identified')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'), IFEO)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\(Debugger)')
    software_output.write('\n')
    software_output.write('NOTE: Entries will only be present if a "Debugger" value was identified')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'), IFEO)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\*')
    software_output.write('\n')
    software_output.write( 'Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters'), CLSID_key_name_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\tRegistry Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\*')
    software_output.write('\n')
    software_output.write( 'Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers'), CLSID_key_name_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\tRegistry Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers\*')
    software_output.write('\n')
    software_output.write( 'Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\PLAP Providers'), CLSID_key_name_lookup)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\tRegistry Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved\*')
    software_output.write('\n')
    software_output.write( 'Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved'),  CLSID_value_name_lookup_2)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('\tRegistry Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{083863F1-70DE-11D0-BD40-00A0C911CE86}\Instance\*')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Wow6432Node\\CLSID\\{083863F1-70DE-11D0-BD40-00A0C911CE86}\\Instance'), CLSID_value_type_lookup_4)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance\*')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Wow6432Node\\CLSID\\{7ED96837-96F0-4812-B211-F13C24117ED3}\\Instance'), CLSID_value_type_lookup_4)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}Instance\*')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Wow6432Node\\CLSID\\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\\Instance'), CLSID_value_type_lookup_4)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

    software_output = open(software_path, 'a+')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')
    software_output.write('HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}Instance\*')
    software_output.write('\n')
    software_output.write('Note: * values were parsed from the corresponding HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('Note: # values were parsed from the corresponding HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{GUID}\InProcServer32\ key')
    software_output.write('\n')
    software_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    software_output.write('\n')

    try:
        parse_recursive(reg_software.open('Classes\\Wow6432Node\\CLSID\\{AC757296-3522-4E11-9862-C17BE5A1767E}\\Instance'), CLSID_value_type_lookup_4)

    except Registry.RegistryKeyNotFoundException:
        software_output.write('\n')
        software_output.write('Key Not Found')
        software_output.write('\n')

        software_output.close()

else:
    print 'SOFTWARE Hive Not Found'

##########################################################################################################################################################################################
#NTUSER Hive Functions

def ntuser_key_value(key):

    key_path = key.path()

    ntuser_output.write('\n')
    ntuser_output.write('Key Path: ' + key.path())
    ntuser_output.write('\n')
    ntuser_output.write('Last Write Time: ' + str(key.timestamp()))
    ntuser_output.write('\n')

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

            x = key_path.split('}')[1]

            if '\\Users\\' in value.value():

                normalized_string = str(value.value().replace("\"", ''))
                start_string = normalized_string[0:9]
                location = normalized_string.find('\\', 10)
                start_location = location
                end_string = normalized_string[start_location:]
                normalized_value = start_string + '[user]' + end_string

                path = str(x) + '\\' + str(value.name()) + '\\' + str(normalized_value)

                path_tracker = []

                for item in rptk_whitelist:
                   path_tracker.append(item)

                if path in rptk_whitelist:
                    ntuser_output.write('\n')
                    ntuser_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), normalized_value))
                    ntuser_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            ntuser_output.write('\n')
                            ntuser_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), normalized_value))
                            ntuser_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                ntuser_output.write('\n')
                                ntuser_output.write('\tBASE64:\t\t\t{}: {}'.format(value.name(), value.value()))
                                ntuser_output.write('\n')
                                ntuser_output.write( '\t\tDECODED:\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                ntuser_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    ntuser_output.write('\n')
                    ntuser_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    ntuser_output.write('\n')

            elif '\\Users\\' not in value.value():

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                if path in rptk_whitelist:
                    ntuser_output.write('\n')
                    ntuser_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    ntuser_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value().lower()):
                            ntuser_output.write('\n')
                            ntuser_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            ntuser_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                ntuser_output.write('\n')
                                ntuser_output.write('\tBASE64:\t\t\t{}: {}'.format(value.name(), value.value()))
                                ntuser_output.write('\n')
                                ntuser_output.write('\t\tDECODED:\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                ntuser_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    ntuser_output.write('\n')
                    ntuser_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    ntuser_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write(key_path)
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

def windows_load_value(key):
    key_path = key.path()

    ntuser_output.write('\n')
    ntuser_output.write('Key Path: ' + key.path())
    ntuser_output.write('\n')
    ntuser_output.write('Last Write Time: ' + str(key.timestamp()))
    ntuser_output.write('\n')

    try:
        for value in key.values():
            if value.name() == 'Load':

                x = key_path.split('}')[1]

                if '\\Users\\' in value.value():

                    normalized_string = str(value.value().replace("\"", ''))
                    start_string = normalized_string[0:9]
                    location = normalized_string.find('\\', 10)
                    start_location = location
                    end_string = normalized_string[start_location:]
                    normalized_value = start_string + '[user]' + end_string

                    path = str(x) + '\\' + str(value.name()) + '\\' + str(normalized_value)

                    path_tracker = []

                    for item in rptk_whitelist:
                        path_tracker.append(item)

                    if path in rptk_whitelist:
                        ntuser_output.write('\n')
                        ntuser_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), normalized_value))
                        ntuser_output.write('\n')
                        path_tracker.remove(path)

                    if path not in rptk_whitelist:
                        for ioc in rptk_iocs:
                            if str(ioc) in str(value.value()).lower():
                                ntuser_output.write('\n')
                                ntuser_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), normalized_value))
                                ntuser_output.write('\n')
                                path_tracker.append(path)

                    path_tracker2 = []

                    for item in rptk_whitelist:
                        path_tracker2.append(item)

                    for item in path_tracker:
                        path_tracker2.append(item)

                    if path not in path_tracker2:
                        b64_list = []
                        b64_list.append(path.split('\\')[-1])

                        for item in b64_list:
                            search_string = ''.join(item.split())
                            search_results = b64_search.findall(str(search_string))
                            result_string = str(search_results)

                            if len(result_string) > 10:
                                if '.' in item:
                                    break;

                                else:
                                    ntuser_output.write('\n')
                                    ntuser_output.write('\tBASE64:\t{}: {}'.format(value.name(), normalized_value))
                                    ntuser_output.write('\n')
                                    ntuser_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                    ntuser_output.write('\n')
                                    path_tracker2.append(path)

                    path_tracker3 = []

                    for item in path_tracker2:
                        path_tracker3.append(item)

                    if path not in path_tracker3:
                        ntuser_output.write('\n')
                        ntuser_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                        ntuser_output.write('\n')

                elif '\\Users\\' not in value.value():

                    path_tracker = []

                    for item in rptk_whitelist:
                        path_tracker.append(item)

                    path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                    if path in rptk_whitelist:
                        ntuser_output.write('\n')
                        ntuser_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                        ntuser_output.write('\n')
                        path_tracker.remove(path)

                    if path not in rptk_whitelist:
                        for ioc in rptk_iocs:
                            if str(ioc) in str(value.value().lower()):
                                ntuser_output.write('\n')
                                ntuser_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                                ntuser_output.write('\n')
                                path_tracker.append(path)

                    path_tracker2 = []

                    for item in rptk_whitelist:
                        path_tracker2.append(item)

                    for item in path_tracker:
                        path_tracker2.append(item)

                    if path not in path_tracker2:
                        b64_list = []
                        b64_list.append(path.split('\\')[-1])

                        for item in b64_list:
                            search_string = ''.join(item.split())
                            search_results = b64_search.findall(str(search_string))
                            result_string = str(search_results)

                            if len(result_string) > 10:
                                if '.' in item:
                                    break;

                                else:
                                    ntuser_output.write('\n')
                                    ntuser_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                    ntuser_output.write('\n')
                                    ntuser_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                    ntuser_output.write('\n')
                                    path_tracker2.append(path)

                    path_tracker3 = []

                    for item in path_tracker2:
                        path_tracker3.append(item)

                    if path not in path_tracker3:
                        ntuser_output.write('\n')
                        ntuser_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                        ntuser_output.write('\n')

        else:
            ntuser_output.write('\n')
            ntuser_output.write('\tLoad Value Not Found')
            ntuser_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write(key_path)
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

def windows_run_value(key):
    key_path = key.path()

    ntuser_output.write('\n')
    ntuser_output.write('Key Path: ' + key.path())
    ntuser_output.write('\n')
    ntuser_output.write('Last Write Time: ' + str(key.timestamp()))
    ntuser_output.write('\n')

    try:
        for value in key.values():
            if value.name() == 'Run':

                x = key_path.split('}')[1]

                if '\\Users\\' in value.value():

                    normalized_string = str(value.value().replace("\"", ''))
                    start_string = normalized_string[0:9]
                    location = normalized_string.find('\\', 10)
                    start_location = location
                    end_string = normalized_string[start_location:]
                    normalized_value = start_string + '[user]' + end_string

                    path = str(x) + '\\' + str(value.name()) + '\\' + str(normalized_value)

                    path_tracker = []

                    for item in rptk_whitelist:
                        path_tracker.append(item)

                    if path in rptk_whitelist:
                        ntuser_output.write('\n')
                        ntuser_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), normalized_value))
                        ntuser_output.write('\n')
                        path_tracker.remove(path)

                    if path not in rptk_whitelist:
                        for ioc in rptk_iocs:
                            if str(ioc) in str(value.value()).lower():
                                ntuser_output.write('\n')
                                ntuser_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), normalized_value))
                                ntuser_output.write('\n')
                                path_tracker.append(path)

                    path_tracker2 = []

                    for item in rptk_whitelist:
                        path_tracker2.append(item)

                    for item in path_tracker:
                        path_tracker2.append(item)

                    if path not in path_tracker2:
                        b64_list = []
                        b64_list.append(path.split('\\')[-1])

                        for item in b64_list:
                            search_string = ''.join(item.split())
                            search_results = b64_search.findall(str(search_string))
                            result_string = str(search_results)

                            if len(result_string) > 10:
                                if '.' in item:
                                    break;

                                else:
                                    ntuser_output.write('\n')
                                    ntuser_output.write('\tBASE64:\t{}: {}'.format(value.name(), normalized_value))
                                    ntuser_output.write('\n')
                                    ntuser_output.write( '\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                    ntuser_output.write('\n')
                                    path_tracker2.append(path)

                    path_tracker3 = []

                    for item in path_tracker2:
                        path_tracker3.append(item)

                    if path not in path_tracker3:
                        ntuser_output.write('\n')
                        ntuser_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                        ntuser_output.write('\n')

                elif '\\Users\\' not in value.value():

                    path_tracker = []

                    for item in rptk_whitelist:
                        path_tracker.append(item)

                    path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                    if path in rptk_whitelist:
                        ntuser_output.write('\n')
                        ntuser_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                        ntuser_output.write('\n')
                        path_tracker.remove(path)

                    if path not in rptk_whitelist:
                        for ioc in rptk_iocs:
                            if str(ioc) in str(value.value().lower()):
                                ntuser_output.write('\n')
                                ntuser_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                                ntuser_output.write('\n')
                                path_tracker.append(path)

                    path_tracker2 = []

                    for item in rptk_whitelist:
                        path_tracker2.append(item)

                    for item in path_tracker:
                        path_tracker2.append(item)

                    if path not in path_tracker2:
                        b64_list = []
                        b64_list.append(path.split('\\')[-1])

                        for item in b64_list:
                            search_string = ''.join(item.split())
                            search_results = b64_search.findall(str(search_string))
                            result_string = str(search_results)

                            if len(result_string) > 10:
                                if '.' in item:
                                    break;

                                else:
                                    ntuser_output.write('\n')
                                    ntuser_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                    ntuser_output.write('\n')
                                    ntuser_output.write( '\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                    ntuser_output.write('\n')
                                    path_tracker2.append(path)

                    path_tracker3 = []

                    for item in path_tracker2:
                        path_tracker3.append(item)

                    if path not in path_tracker3:
                        ntuser_output.write('\n')
                        ntuser_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                        ntuser_output.write('\n')

        else:
            ntuser_output.write('\n')
            ntuser_output.write('\tRun Value Not Found')
            ntuser_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write(key_path)
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

sys.stdout.write('\n')
sys.stdout.write('Processing NTUSER Hive')
sys.stdout.write('\n')

if os.path.isfile('NTUSER.DAT'):
    open_ntuser = open('NTUSER.DAT', "rb")
    reg_ntuser = Registry.Registry(open_ntuser)
    ntuser_path = os.path.join(output_dir, 'ntuser_persistence.txt')
    ntuser_output = open(ntuser_path, 'a+')

    ntuser_output.write('##############################################################################################################################################################')
    ntuser_output.write('\n')
    ntuser_output.write('\n')
    ntuser_output.write('Registry Persistence Toolkit (RPTK) v1.0')
    ntuser_output.write('\n')
    ntuser_output.write('@kpoppenwimer')
    ntuser_output.write('\n')
    ntuser_output.write('\n')
    ntuser_output.write('##############################################################################################################################################################')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\Run'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Run')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Wow6432Node\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_ouput.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnceEx')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunServices')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\RunServices'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Wow6432Node\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'), ntuser_key_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows NT\CurrentVersion\Windows\(Load)')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), windows_load_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

    ntuser_output = open(ntuser_path, 'a+')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')
    ntuser_output.write('NTUSER.DAT\Software\Microsoft\Windows NT\CurrentVersion\Windows\(Run)')
    ntuser_output.write('\n')
    ntuser_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    ntuser_output.write('\n')

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), windows_run_value)

    except Registry.RegistryKeyNotFoundException:
        ntuser_output.write('\n')
        ntuser_output.write('Key Not Found')
        ntuser_output.write('\n')

        ntuser_output.close()

else:
    print 'NTUSER Hive Not Found'

#SYSTEM Hive Functions

def current_controlset_value(key):

    key_path = key.path()

    system_output.write('\n')
    system_output.write('Key Path: ' + key.path())
    system_output.write('\n')
    system_output.write('Last Write time: ' + str(key.timestamp()))
    system_output.write('\n')

    try:
        for value in key.values():
            if value.name() == 'Current':

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                if path in rptk_whitelist:
                    system_output.write('\n')
                    system_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    system_output.write('\n')

                elif path not in rptk_whitelist:
                    system_output.write('\n')
                    system_output.write('\tSUSPICIOUS - IOC:\t{}: {}'.format(value.name(), value.value()))
                    system_output.write('\n')

                global current_controlset
                current_controlset = value.value()
                return current_controlset

    except Registry.RegistryKeyNotFoundException:
        system_output.write(key_path())
        system_output.write('Key Not Found')
        system_output.write('\n')

        system_output.close()

def system_key_value(key):
    key_path = key.path()
    system_output.write('\n')
    system_output.write('Key Path: ' + key.path())
    system_output.write('\n')
    system_output.write('Last Write Time: ' + str(key.timestamp()))
    system_output.write('\n')

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

            x = key_path.split('}')[1]
            path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

            path_tracker = []

            for item in rptk_whitelist:
                path_tracker.append(item)

            if path in rptk_whitelist:
                system_output.write('\n')
                system_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                system_output.write('\n')
                path_tracker.remove(path)

            if path not in rptk_whitelist:
                for ioc in rptk_iocs:
                    if str(ioc) in str(value.value()).lower():
                        system_output.write('\n')
                        system_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                        system_output.write('\n')
                        path_tracker.append(path)

            path_tracker2 = []

            for item in rptk_whitelist:
                path_tracker2.append(item)

            for item in path_tracker:
                path_tracker2.append(item)

            if path not in path_tracker2:
                b64_list = []
                b64_list.append(path.split('\\')[-1])

                for item in b64_list:
                    search_string = ''.join(item.split())
                    search_results = b64_search.findall(str(search_string))
                    result_string = str(search_results)

                    if len(result_string) > 10:
                        if '.' in item:
                            break;

                        else:
                            system_output.write('\n')
                            system_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                            system_output.write('\n')
                            system_output.write( '\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                            system_output.write('\n')
                            path_tracker2.append(path)

            path_tracker3 = []

            for item in path_tracker2:
                path_tracker3.append(item)

            if path not in path_tracker3:
                system_output.write('\n')
                system_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                system_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write(key_path)
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

        system_output.close()

def services_imagepath_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'ImagePath':

                system_output.write('\n')
                system_output.write('Key Path: ' + key.path())
                system_output.write('\n')
                system_output.write('Last Write time: ' + str(key.timestamp()))
                system_output.write('\n')

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    system_output.write('\n')
                    system_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    system_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            system_output.write('\n')
                            system_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            system_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                system_output.write('\n')
                                system_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                system_output.write('\n')
                                system_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                system_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    system_output.write('\n')
                    system_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    system_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write(key_path())
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

def sessionmgr_bootexecute_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'BootExecute':

                system_output.write('\n')
                system_output.write('Key Path: ' + key.path())
                system_output.write('\n')
                system_output.write('Last Write time: ' + str(key.timestamp()))
                system_output.write('\n')

                x = key_path.split('}')[1]
                path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

                path_tracker = []

                for item in rptk_whitelist:
                    path_tracker.append(item)

                if path in rptk_whitelist:
                    system_output.write('\n')
                    system_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                    system_output.write('\n')
                    path_tracker.remove(path)

                if path not in rptk_whitelist:
                    for ioc in rptk_iocs:
                        if str(ioc) in str(value.value()).lower():
                            system_output.write('\n')
                            system_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                            system_output.write('\n')
                            path_tracker.append(path)

                path_tracker2 = []

                for item in rptk_whitelist:
                    path_tracker2.append(item)

                for item in path_tracker:
                    path_tracker2.append(item)

                if path not in path_tracker2:
                    b64_list = []
                    b64_list.append(path.split('\\')[-1])

                    for item in b64_list:
                        search_string = ''.join(item.split())
                        search_results = b64_search.findall(str(search_string))
                        result_string = str(search_results)

                        if len(result_string) > 10:
                            if '.' in item:
                                break;

                            else:
                                system_output.write('\n')
                                system_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                                system_output.write('\n')
                                system_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                                system_output.write('\n')
                                path_tracker2.append(path)

                path_tracker3 = []

                for item in path_tracker2:
                    path_tracker3.append(item)

                if path not in path_tracker3:
                    system_output.write('\n')
                    system_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                    system_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write(key_path())
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

def winsock2_catalog_entries(key):

    key_path = key.path()
    system_output.write('\n')
    system_output.write('Key Path: ' + key.path())
    system_output.write('\n')
    system_output.write('Last Write Time: ' + str(key.timestamp()))
    system_output.write('\n')

    try:
        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

            x = key_path.split('}')[1]
            path = str(x) + '\\' + str(value.name()) + '\\' + str(value.value())

            path_tracker = []

            for item in rptk_whitelist:
                path_tracker.append(item)

            if path in rptk_whitelist:
                system_output.write('\n')
                system_output.write('\tWHITELISTED:\t{}: {}'.format(value.name(), value.value()))
                system_output.write('\n')
                path_tracker.remove(path)

            if path not in rptk_whitelist:
                for ioc in rptk_iocs:
                    if str(ioc) in str(value.value()).lower():
                        system_output.write('\n')
                        system_output.write('\tSUSPICIOUS IOC:\t{}: {}'.format(value.name(), value.value()))
                        system_output.write('\n')
                        path_tracker.append(path)

            path_tracker2 = []

            for item in rptk_whitelist:
                path_tracker2.append(item)

            for item in path_tracker:
                path_tracker2.append(item)

            if path not in path_tracker2:
                b64_list = []
                b64_list.append(path.split('\\')[-1])

                for item in b64_list:
                    search_string = ''.join(item.split())
                    search_results = b64_search.findall(str(search_string))
                    result_string = str(search_results)

                    if len(result_string) > 10:
                        if '.' in item:
                            break;

                        else:
                            system_output.write('\n')
                            system_output.write('\tBASE64:\t{}: {}'.format(value.name(), value.value()))
                            system_output.write('\n')
                            system_output.write('\t\tDECODED:\t\t{}: '.format(value.name()) + base64.b64decode(result_string))
                            system_output.write('\n')
                            path_tracker2.append(path)

            path_tracker3 = []

            for item in path_tracker2:
                path_tracker3.append(item)

            if path not in path_tracker3:
                system_output.write('\n')
                system_output.write('\tREVIEW:\t\t\t{}: {}'.format(value.name(), value.value()))
                system_output.write('\n')

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write(key_path)
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

sys.stdout.write('\n')
sys.stdout.write('Processing System Hive')
sys.stdout.write('\n')

if os.path.isfile('SYSTEM'):

    open_system = open('SYSTEM', "rb")
    reg_system = Registry.Registry(open_system)
    system_path = os.path.join(output_dir, 'system_persistence.txt')
    system_output = open(system_path, 'a+')

    system_output.write('##############################################################################################################################################################')
    system_output.write('\n')
    system_output.write('\n')
    system_output.write('Registry Persistence Toolkit (RPTK) v1.0')
    system_output.write('\n')
    system_output.write('@kpoppenwimer')
    system_output.write('\n')
    system_output.write('\n')
    system_output.write('##############################################################################################################################################################')
    system_output.write('\n')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')
    system_output.write('HKLM\SYSTEM\Select\(Current)')
    system_output.write('\n')
    system_output.write('This key determines what the current control set is (ControlSet001, 002, 003, etc.)')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')

    try:
        parse_recursive(reg_system.open('Select'), current_controlset_value)

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

        system_output.close()

    system_output = open(system_path, 'a+')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')
    system_output.write('HKLM\SYSTEM\CurrentControlSet\Services\*\(ImagePath)')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Services'), services_imagepath_value)

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

        system_output.close()

    system_output = open(system_path, 'a+')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')
    system_output.write('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\(BootExecute)')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Control\\Session Manager'), sessionmgr_bootexecute_value)

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

        system_output.close()

    system_output = open(system_path, 'a+')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')
    system_output.write('HKLM\SYSTEM\CurrentControlSet\Services\Winsock2\Parameters\NameSpace_Catalog5\Catalog_Entries\*')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Services\Winsock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries'), winsock2_catalog_entries)

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

        system_output.close()

    system_output = open(system_path, 'a+')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')
    system_output.write('HKLM\SYSTEM\CurrentControlSet\Services\Winsock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\*')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Services\Winsock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64'), winsock2_catalog_entries)

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

        system_output.close()

    system_output = open(system_path, 'a+')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')
    system_output.write('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDlls')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Control\\Session Manager\\KnownDlls'), system_key_value)

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

        system_output.close()

    system_output = open(system_path, 'a+')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')
    system_output.write('HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order')
    system_output.write('\n')
    system_output.write('--------------------------------------------------------------------------------------------------------------------------------------------------------------')
    system_output.write('\n')

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Control\\NetworkProvider\\Order'), system_key_value)

    except Registry.RegistryKeyNotFoundException:
        system_output.write('\n')
        system_output.write('Key Not Found')
        system_output.write('\n')

        system_output.close()

else:
    print 'SYSTEM Hive Not Found'

end_time = datetime.datetime.now()
sys.stdout.write('\n')
sys.stdout.write('Processing Completed: ' + str(end_time).split(".")[0])
sys.stdout.write('\n')
sys.stdout.write('\n')
sys.stdout.write('Total Processing Time: ' + str(end_time - start_time).split(".")[0])
sys.stdout.write('\n')
sys.stdout.write('\n')