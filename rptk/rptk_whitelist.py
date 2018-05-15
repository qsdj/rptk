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

sys.stdout.write('\n')
sys.stdout.write('#############################################')
sys.stdout.write('\n')
sys.stdout.write('        RPTK Whitelist Generator v1.0        ')
sys.stdout.write('\n')
sys.stdout.write('#############################################')
sys.stdout.write('\n')

argparser = argparse.ArgumentParser()

argparser.add_argument('-d', '--dir', dest='dir_path', type=str, action='store', default=None, required=True, help='Directory path to registry files', metavar = '')
argparser.add_argument('-o', '--output', dest='output_dir', type=str, action='store', default=None, required=True, help='Directory path to output location', metavar = '')

args = argparser.parse_args()
dir_path = args.dir_path
os.chdir(dir_path)
output_dir = args.output_dir

#Global Hive Function

def parse_recursive(key, f):
    f(key)
    for subkey in key.subkeys():
        parse_recursive(subkey, f)

def software_key_value(key):
    key_path = key.path()

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;


def CLSID_value_type_lookup(key):
    key_path = key.path()

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

        p = '%s' % value.value()
        clsid_list = [str(p)]

        for x in clsid_list:
            try:
                clsid_value = reg_software.open('Classes\\CLSID\\' + str(p) + '\\InProcServer32')
                clsid_path = str('\\Classes\\CLSID\\' + str(p) + '\\InProcServer32')

                for i, value in enumerate(clsid_value.values()):
                    rptk_whitelist.write(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

                clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(p) + '\\InProcServer32')

                for i, value in enumerate(clsid_value2.values()):
                    rptk_whitelist.write(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

            except:
                pass;
    except:
        pass;


def CLSID_value_name_lookup_2(key): #
    key_path = key.path()

    clsid_list = []
    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
                clsid_list.append(str(value.name()))

        for x in clsid_list:
            try:
                clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                for i, value in enumerate(clsid_value.values()):
                    rptk_whitelist.write(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

                clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                for i, value in enumerate(clsid_value2.values()):
                    rptk_whitelist.write(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

            except:
                pass;
    except:
        pass;


def CLSID_value_type_lookup_3(key):
    key_path = key.path()
    clsid_list2 = [str(key_path.rsplit('\\', 1)[1])]

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

        p = '%s' % value.value()
        clsid_list = [str(p)]

        for x in clsid_list:
            try:
                clsid_value = reg_software.open('Classes\\CLSID\\' + str(p) + '\\InProcServer32')
                clsid_path = str('\\Classes\\CLSID\\' + str(p) + '\\InProcServer32')

                for i, value in enumerate(clsid_value.values()):
                    rptk_whitelist.write(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

                clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(p) + '\\InProcServer32')

                for i, value in enumerate(clsid_value2.values()):
                    rptk_whitelist.write(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

            except:
                pass;

        for x in clsid_list2:
            try:
                clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path3 = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                for i, value in enumerate(clsid_value.values()):
                    rptk_whitelist.write(str(clsid_path3) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

                clsid_value = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path4 = ('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                for i, value in enumerate(clsid_value.values()):
                    rptk_whitelist.write(str(clsid_path4) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

            except Registry.RegistryKeyNotFoundException:
                pass
    except:
        pass;


def CLSID_value_type_lookup_4(key):
    key_path = key.path()

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

                p = '%s' % value.value()
                clsid_list = [str(p)]

                for x in clsid_list:
                    try:
                        clsid_value = reg_software.open('Classes\\CLSID\\' + str(p) + '\\InProcServer32')
                        clsid_path = str('\\Classes\\CLSID\\' + str(p) + '\\InProcServer32')

                        for i, value in enumerate(clsid_value.values()):
                            rptk_whitelist.write(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))
                            rptk_whitelist.write('\n')

                        clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                        clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(p) + '\\InProcServer32')

                        for i, value in enumerate(clsid_value2.values()):
                            rptk_whitelist.write(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))
                            rptk_whitelist.write('\n')

                    except:
                        pass;
    except:
        pass;

def CLSID_key_name_lookup(key):
    key_path = key.path()

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

        clsid_list = [str(key_path.rsplit('\\', 1)[1])]

        for x in clsid_list:
            try:
                clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                for i, value in enumerate(clsid_value.values()):
                    rptk_whitelist.write(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

                clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                for i, value in enumerate(clsid_value2.values()):
                    rptk_whitelist.write(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')

            except:
                pass;
    except:
        pass;

def SharedTaskScheduler(key):
    key_path = key.path()

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

                p = '%s' % value.name()
                clsid_list = [str(p)]

                for x in clsid_list:
                    try:
                        clsid_value = reg_software.open('Classes\\CLSID\\' + str(x) + '\\InProcServer32')
                        clsid_path = str('\\Classes\\CLSID\\' + str(x) + '\\InProcServer32')

                        for i, value in enumerate(clsid_value.values()):
                            rptk_whitelist.write(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))
                            rptk_whitelist.write('\n')

                        clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                        clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')

                        for i, value in enumerate(clsid_value2.values()):
                            rptk_whitelist.write(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))
                            rptk_whitelist.write('\n')

                    except:
                        pass;
    except:
        pass;


def winlogon_values(key):
    key_path = key.path()

    try:

        for value in key.values():

            if value.name() == 'Userinit':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() =='VMApplet':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() =='Shell':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() =='AppSetup':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() =='GinaDLL':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() =='LsaStart':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() =='SaveDumpStart':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() == 'ServiceControllerStart':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() == 'System':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() == 'Taskman':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

            elif value.name() == 'UIHost':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

def notify_dllname_value(key):
    key_path =key.path

    try:
        for value in key.values():
            if value.name() == 'DLLName':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;


def stub_path_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'StubPath':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

def appinit_dlls_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'AppInit_DLLs':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

def IconServiceLib_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'IconServiceLib':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

def scripts_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'Scripts':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

    except:
        pass;

def cmdar_key_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'AutoRun':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

def common_startup_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'Common Startup':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

def IETB(key):
    key_path = key.path()

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ or v.value_type() == Registry.RegBin]:

            x = key_path.split('}')[1]
            rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
            rptk_whitelist.write('\n')

            p = '%s' % value.name()
            clsid_list = [str(p)]

            for x in clsid_list:
                try:
                    clsid_value = reg_software.open('Classes\\CLSID\\' + str(p) + '\\InProcServer32')
                    clsid_path = str('\\Classes\\CLSID\\' + str(p) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value.values()):
                        rptk_whitelist.write(str(clsid_path) + '\\' + str(value.name()) + '\\' + str(value.value()))
                        rptk_whitelist.write('\n')

                    clsid_value2 = reg_software.open('Classes\\Wow6432Node\\CLSID\\' + str(x) + '\\InProcServer32')
                    clsid_path2 = str('\\Classes\\Wow6432Node\\CLSID\\' + str(p) + '\\InProcServer32')

                    for i, value in enumerate(clsid_value2.values()):
                        rptk_whitelist.write(str(clsid_path2) + '\\' + str(value.name()) + '\\' + str(value.value()))
                        rptk_whitelist.write('\n')

                except:
                    pass;
    except:
        pass;

def IFEO(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'Debugger':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

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
    whitelist_path = os.path.join(output_dir, 'rptk_whitelist.txt')
    rptk_whitelist = open(whitelist_path, 'a+')

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Run'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\RunOnce'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\RunOnceEx'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\RunServices'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\RunServicesOnce'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Winlogon'), winlogon_values)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify'), notify_dllname_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Active Setup\\Installed Components'), stub_path_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Active Setup\\Installed Components'), stub_path_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\\'), CLSID_value_type_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\\'), CLSID_value_type_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Windows'), appinit_dlls_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), appinit_dlls_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Windows'), IconServiceLib_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Policies\\Microsoft\\Windows\\System\\Scripts'), scripts_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler\\'), SharedTaskScheduler)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler\\'), SharedTaskScheduler)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Command Processor'), cmdar_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Command Processor'), cmdar_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders'), common_startup_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders'), common_startup_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\batfile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\cmdfile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\comfile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\exefile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\htafile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\htmlfile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\htmlfile\\shell\\opennew\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\https\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\internetshortcut\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\jsefile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\piffile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\regfile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\srcfile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\txtfile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\vbsfile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\wsffile\\shell\\open\\command'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\*\\ShellEx\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\*\\ShellEx\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\*\\ShellEx\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\*\\ShellEx\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\AllFileSystemObjects\\ShellEx\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\AllFileSystemObjects\\ShellEx\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\AllFileSystemObjects\\ShellEx\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\AllFileSystemObjects\\ShellEx\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\AllFileSystemObjects\\ShellEx\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\AllFileSystemObjects\\ShellEx\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\CLSID\\{083863F1-70DE-11D0-BD40-00A0C911CE86}\\Instance'), CLSID_value_type_lookup_4)

    except:
        pass;


    try:
        parse_recursive(reg_software.open('Classes\\CLSID\\{7ED96837-96F0-4812-B211-F13C24117ED3}\\Instance'), CLSID_value_type_lookup_4)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\CLSID\\{AC757296-3522-4E11-9862-C17BE5A1767E}\\Instance'), CLSID_value_type_lookup_4)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\CLSID\\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\\Instance'), CLSID_value_type_lookup_4)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\Background\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\Background\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\shellex\\CopyHookHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\shellex\\CopyHookHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\shellex\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\shellex\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Directory\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except:
        pass

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Directory\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Drive\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Drive\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Drive\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\ColumnHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\ColumnHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\ContextMenuHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\DragDropHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\ExtShellFolderViews'), CLSID_value_type_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\ExtShellFolderViews'), CLSID_value_type_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Folder\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Classes\\Folder\\shellex\\PropertySheetHandlers'), CLSID_value_type_lookup_3)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\PROTOCOLS\\Filter'), CLSID_value_type_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\PROTOCOLS\\Handler'), CLSID_value_type_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Drivers32'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers'), CLSID_value_type_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers'), CLSID_value_type_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Internet Explorer\\Extensions'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Internet Explorer\\Extensions'), software_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Internet Explorer\\Toolbar'), IETB)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar'), IETB)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'), IFEO)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'), IFEO)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved'), CLSID_value_name_lookup_2)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved'), CLSID_value_name_lookup_2)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Wow6432Node\\CLSID\\{083863F1-70DE-11D0-BD40-00A0C911CE86}\\Instance'), CLSID_value_type_lookup_4)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Wow6432Node\\CLSID\\{7ED96837-96F0-4812-B211-F13C24117ED3}\\Instance'), CLSID_value_type_lookup_4)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Wow6432Node\\CLSID\\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\\Instance'), CLSID_value_type_lookup_4)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Classes\\Wow6432Node\\CLSID\\{AC757296-3522-4E11-9862-C17BE5A1767E}\\Instance'), CLSID_value_type_lookup_4)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\'), CLSID_key_name_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjects'), CLSID_key_name_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjects'), CLSID_key_name_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters'), CLSID_key_name_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers'), CLSID_key_name_lookup)

    except:
        pass;

    try:
        parse_recursive(reg_software.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\PLAP Providers'), CLSID_key_name_lookup)

    except:
        pass;

############################################################################################################################################################################################
#NTUSER White List

def ntuser_key_value(key):
    key_path = key.path()

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

                    rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(normalized_value))
                    rptk_whitelist.write('\n')

                else:

                    rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')
    except:
        pass;

def windows_load_value(key):
    key_path = key.path()

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

                    rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(normalized_value))
                    rptk_whitelist.write('\n')

                else:

                    rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')
    except:
        pass;

def windows_run_value(key):
    key_path = key.path()

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

                    rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(normalized_value))
                    rptk_whitelist.write('\n')

                else:

                    rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                    rptk_whitelist.write('\n')
    except:
        pass;


sys.stdout.write('\n')
sys.stdout.write('Processing NTUSER Hive')
sys.stdout.write('\n')

if os.path.isfile('NTUSER.DAT'):
    open_ntuser = open('NTUSER.DAT', "rb")
    reg_ntuser = Registry.Registry(open_ntuser)
    whitelist_path = os.path.join(output_dir, 'rptk_whitelist.txt')
    rptk_whitelist = open(whitelist_path, 'a+')


    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\Run'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Wow6432Node\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run'), ntuser_key_value)
    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\RunServices'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Wow6432Node\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'), ntuser_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), windows_load_value)

    except:
        pass;

    try:
        parse_recursive(reg_ntuser.open('Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows'), windows_run_value)

    except:
        pass;

def current_controlset_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'Current':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')

                global current_controlset
                current_controlset = value.value()
                return current_controlset
    except:
        pass;

def system_key_value(key):
    key_path = key.path()

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

def services_imagepath_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'ImagePath':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

def sessionmgr_bootexecute_value(key):
    key_path = key.path()

    try:
        for value in key.values():
            if value.name() == 'BootExecute':
                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;

def winsock2_catalog_entries(key):
    key_path = key.path()

    try:

        for value in [v for v in key.values()
            if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:

                x = key_path.split('}')[1]
                rptk_whitelist.write(str(x) + '\\' + str(value.name()) + '\\' + str(value.value()))
                rptk_whitelist.write('\n')
    except:
        pass;


sys.stdout.write('\n')
sys.stdout.write('Processing System Hive')
sys.stdout.write('\n')

if os.path.isfile('System'):
    open_system = open('System', "rb")
    reg_system = Registry.Registry(open_system)
    whitelist_path = os.path.join(output_dir, 'rptk_whitelist.txt')
    rptk_whitelist = open(whitelist_path, 'a+')

    try:
        parse_recursive(reg_system.open('Select'), current_controlset_value)

    except:
        pass;

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Services'), services_imagepath_value)

    except:
        pass;

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Control\\Session Manager'), sessionmgr_bootexecute_value)

    except:
        pass;

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Services\Winsock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries'), winsock2_catalog_entries)

    except:
        pass

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Services\Winsock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64'), winsock2_catalog_entries)

    except:
        pass;

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Control\\Session Manager\\KnownDlls'), system_key_value)

    except:
        pass;

    try:
        parse_recursive(reg_system.open('ControlSet00' + str(current_controlset) + '\\Control\\NetworkProvider\\Order'), system_key_value)

    except:
        pass;

end_time = datetime.datetime.now()
sys.stdout.write('\n')
sys.stdout.write('Processing Completed: ' + str(end_time).split(".")[0])
sys.stdout.write('\n')
sys.stdout.write('\n')
sys.stdout.write('Total Processing Time: ' + str(end_time - start_time).split(".")[0])
sys.stdout.write('\n')
sys.stdout.write('\n')
