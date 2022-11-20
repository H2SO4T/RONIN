import os
import glob
import json
import pickle
import platform
import signal
import subprocess
import configparser
import time
from shlex import split as sh_split
from androguard.misc import sign_apk
from networkx.drawing.nx_pydot import read_dot
from dynamic_analysis.utils.timer import Timer
from dynamic_analysis.generator import Generator
from dynamic_analysis.DeepICC.ICC_env import ICCEnv
from dynamic_analysis.DeepICC.exploration import SACAlgorithm
from dynamic_analysis.ares.rl_interaction.RL_application_env import RLApplicationEnv
from dynamic_analysis.ares.rl_interaction.algorithms.RandomExploration import RandomAlgorithm
from dynamic_analysis.ares.rl_interaction.utils.utils import AppiumLauncher, EmulatorLauncher


def retrieve_vulnerabilities(pardir: str, vulname: str):
    vuln_path = os.path.join(pardir, f'{vulname}.json')
    if os.path.isfile(vuln_path):
        with open(vuln_path) as f:
            return json.load(f)
    else:
        return None


def generate_values(extra_type: str, size: int = 5):
    if extra_type == '--es':
        return [Generator.generate_string() for x in range(size)]
    if extra_type in ['--ed', '--ef']:
        return [Generator.generate_numbers() for x in range(size)]
    if extra_type in ['--ei', '--el']:
        return [int(Generator.generate_numbers()) for x in range(size)]
    if extra_type == '-t':
        return [Generator.generate_types() for x in range(size)]
    if extra_type == '--ez':
        return [True, False]


def digest_extra_dict(extra_dict):
    extra_dict_map = {
        "getStringExtra": '--es',
        "get": '--es',
        "getString": '--es',
        "setType": '-t',
        "getCharExtra": '--es',
        "getChar": '--es',
        "getDoubleExtra": '--ed',
        "getDouble": '--ed',
        "getFloatExtra": '--ef',
        "getFloat": '--ef',
        "getIntExtra": '--ei',
        "getBoolean": '--ez',
        "getInt": '--ei',
        "getShortExtra": '--ei',
        "getShort": '--ei',
        "getLongExtra": '--el',
        "putExtra": '--es',
        "putInt": '--ei',
        "getData": '-d',
        "getDataString": '--es',
        "getExtras": '--es',
        "getFlags": '-f',
        "getPackage": '-es',
        "getType": '-t',
        "parseUri": '--es',
        "setData": '-d'
    }

    single_values = ['-t', '-f', '-d']

    extra_values_map = dict()
    for key, value in extra_dict.items():
        values = list()
        for extra_key, extra_value in value.items():
            if key in extra_dict_map.keys():
                if extra_dict_map[key] in single_values:
                    if extra_dict_map[key] == '-d':
                        values.append('https://test.com')
                    else:
                        values.append(extra_key)
                    extra_values_map[extra_dict_map[key]] = values
                else:
                    if extra_dict_map[key] in ['--ei', '--el']:
                        temp = list()
                        for st in range(0, len(extra_value)):
                            try:
                                temp.append(int(extra_value[st]))
                            except:
                                pass
                        extra_value = temp[:]
                    extra_value = list(set(extra_value)) + generate_values(extra_type=extra_dict_map[key])
                    extra_values_map[f'{extra_dict_map[key]} {extra_key}'] = extra_value
    return extra_values_map


def start_dynamic_analysis(app_path: str, app_name: str):
    app_versions = glob.glob(os.path.join(app_path, '**', '*.apk'))
    # retrieving the extra dictionary
    extra_dict_path = os.path.join(app_path, f'{app_name}callGraph.json')
    # apk info
    f = open(os.path.join(app_path, 'apk_info_file.pkl'), 'rb')
    apk_info = pickle.load(f)
    f.close()

    extra_dict = None
    if os.path.isfile(extra_dict_path):
        f = open(extra_dict_path)
        extra_dict = json.load(f)
        extra_dict = digest_extra_dict(extra_dict)

    # loading vulnerabilities
    for app in app_versions:
        uber_signer_path = os.path.join(os.path.dirname(__file__), 'utils', 'uber-apk-signer-1.2.1.jar')
        java_command = sh_split(f'java -jar {uber_signer_path} -a {app} --overwrite --allowResign')
        subprocess.call(java_command, timeout=10000)
        # loading vulnerabilities
        pardir = os.path.dirname(app)
        idos = retrieve_vulnerabilities(pardir, 'IDOS')
        fi = retrieve_vulnerabilities(pardir, 'FI')
        xas = retrieve_vulnerabilities(pardir, 'XAS')
        dot_file = read_dot(os.path.join(pardir, 'graph.dot'))

        for activity in apk_info.exported_activities:
            if len(activity['actions']) == 0:
                activity['actions'] = ['']
            for action in activity['actions']:
                if idos is not None:
                    for vulnerability in idos:
                        launch_DeepICC('/.'.join(activity['activity'].rsplit('.', 1)), extra_dict, app, app_name,
                                       apk_info, dot_file,
                                       vulnerability_type='IDOS',
                                       vulnerability=vulnerability, pardir=pardir, type_intent='activity',
                                       action=action)
                if fi is not None:
                    for vulnerability in fi:
                        launch_DeepICC('/.'.join(activity['activity'].rsplit('.', 1)), extra_dict, app, app_name,
                                       apk_info, dot_file,
                                       vulnerability_type='FI',
                                       vulnerability=vulnerability, pardir=pardir, type_intent='activity',
                                       action=action)
                if xas is not None:
                    for vulnerability in xas:
                        launch_DeepICC('/.'.join(activity['activity'].rsplit('.', 1)), extra_dict, app, app_name,
                                       apk_info, dot_file,
                                       vulnerability_type='XAS',
                                       vulnerability=vulnerability, pardir=pardir, type_intent='activity',
                                       action=action)

        # Broadcasts
        for receiver in apk_info.receivers:
            if len(receiver['actions']) == 0:
                receiver['actions'] = ['']
            for action in receiver['actions']:
                if idos is not None:
                    for vulnerability in idos:
                        launch_DeepICC('/.'.join(receiver['name'].rsplit('.', 1)), extra_dict, app, app_name, apk_info,
                                       dot_file,
                                       vulnerability_type='IDOS',
                                       vulnerability=vulnerability, pardir=pardir, type_intent='broadcast',
                                       action=action)
                if fi is not None:
                    for vulnerability in fi:
                        launch_DeepICC('/.'.join(receiver['name'].rsplit('.', 1)), extra_dict, app, app_name, apk_info,
                                       dot_file,
                                       vulnerability_type='FI',
                                       vulnerability=vulnerability, pardir=pardir, type_intent='broadcast',
                                       action=action)
                if xas is not None:
                    for vulnerability in xas:
                        launch_DeepICC('/.'.join(receiver['name'].rsplit('.', 1)), extra_dict, app, app_name, apk_info,
                                       dot_file,
                                       vulnerability_type='XAS',
                                       vulnerability=vulnerability, pardir=pardir, type_intent='broadcast',
                                       action=action)


def close_old_appium_services():
    system = platform.system()
    if system == 'Windows':
        os.system('taskkill /f /im node.exe')
    else:
        os.system('killall node')
        os.system('killall adb')
        time.sleep(2)
        os.system('adb start-server')


def launch_DeepICC(intent_target, extra_parameters, apk_path, app_name, apk_info, dot_file, vulnerability_type,
                   vulnerability, pardir, type_intent, action):
    if extra_parameters is not None and len(extra_parameters.keys()) > 0:
        close_old_appium_services()
        config = configparser.ConfigParser()
        config.read(os.path.join(os.path.dirname(__file__), "config.ini"))
        algo = config["DEFAULT"]["algo"]
        trials_per_app = int(config["DEFAULT"]["trials_per_app"])
        internet = config["DEFAULT"]["internet"]
        if internet == 'True':
            internet = True
        else:
            internet = False
        if config["DEFAULT"]["real_device"] == 'True':
            real_device = True
        else:
            real_device = False

        emu = config["DEFAULT"]["emu"]
        appium_port = config["DEFAULT"]["appium_port"]
        android_port = config["DEFAULT"]["android_port"]
        timer = int(config["DEFAULT"]["timer"])
        timesteps = int(config["DEFAULT"]["timesteps"])
        max_timesteps = int(config["DEFAULT"]["max_timesteps"])
        udid = config["DEFAULT"]["udid"]
        android_v = config["DEFAULT"]["android_v"]
        iterations = config["DEFAULT"]["iterations"]
        device_name = config["DEFAULT"]["device_name"]
        pool_strings = config["DEFAULT"]["pool_strings"]
        cycle = 0
        log_dir = os.path.join(os.getcwd(), 'logs', app_name, algo, str(cycle))
        os.makedirs(log_dir, exist_ok=True)
        widget_list = []
        bug_set = set()
        visited_activities = []
        emulator = None
        clicked_buttons = []
        number_bugs = []
        os.system('killall node')
        time.sleep(2)
        appium = AppiumLauncher(appium_port)
        if not real_device:
            emulator = EmulatorLauncher(emu, device_name, android_port)
        list_activities = list()
        for act in apk_info.activities:
            list_activities.append(act['activity'])
        app = RLApplicationEnv(coverage_dict={}, app_path=apk_path,
                               list_activities=list_activities,
                               widget_list=widget_list, bug_set=bug_set,
                               coverage_dir='',
                               log_dir='',
                               visited_activities=visited_activities,
                               clicked_buttons=clicked_buttons,
                               number_bugs=number_bugs,
                               string_activities='*',
                               appium_port=appium_port,
                               internet=internet,
                               instr_emma=False,
                               instr_jacoco=False,
                               merdoso_button_menu=True,
                               rotation=False,
                               platform_name='Android',
                               platform_version=android_v,
                               udid=udid,
                               pool_strings=pool_strings,
                               device_name=device_name,
                               max_episode_len=max_timesteps,
                               is_headless=False, appium=appium, emulator=emulator,
                               package=apk_info.package, exported_activities=apk_info.exported_activities,
                               services=[], receivers=apk_info.receivers)

        env = ICCEnv(app, vulnerability, dot_file, intent_target=intent_target, intent_action=action,
                     extra_parameters=extra_parameters, list_activities=list_activities, type_intent=type_intent,
                     udid=udid, vulnerability_type=vulnerability_type)

        SACAlgorithm.explore(env, timesteps=timesteps, timer=timer)
        os.kill(env.bug_proc_pid, signal.SIGKILL)
        # generating the correct filename (!!)
        count = 0
        file_name = os.path.join(pardir, f'dynamic_{vulnerability_type}_{apk_info.package}_{count}.txt')
        while True:
            if not os.path.exists(file_name):
                break
            else:
                count += 1
                file_name = os.path.join(pardir, f'dynamic_{vulnerability_type}_{apk_info.package}_{count}.txt')

        with open(file_name, 'a') as f:
            if len(env.true_positives) > 0:
                f.write(str(env.true_positives))
            elif len(env.true_positives) == 0 and env.potentially_not_a_vulnerability:
                f.write(f'The tool reached the target, but did not generate any '
                        f'vulnerability related to: {vulnerability_type}, {vulnerability}')
            else:
                f.write(f'The tool did not reach the target related to: {vulnerability_type}, {vulnerability}')
        if emulator is not None:
            emulator.terminate()
        appium.terminate()
        return 0

    else:
        with open(os.path.join(pardir, f'dynamic_{vulnerability_type}_{apk_info.package}.txt'), 'a') as f:
            f.write(f'The following vulnerability seems to be indirect: {vulnerability_type}, {vulnerability}')
            return 0
