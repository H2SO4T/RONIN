import os
import platform
import subprocess
from static_analysis.apk_info import apkInfo
import pickle
from shlex import split as sh_split
from static_analysis import apk_analyzer
from os.path import exists


def start_static_analysis(apk_path):
    # Here we collect everything that could be useful during the dynamic analysis
    try:
        exported_activities, services, receivers, providers, activities, package = apk_analyzer.analyze(apk_path)
    except Exception:
        print('analysis failed')
        return False, 'null'
    # Now it's the SOOT turn
    android_jar_path = os.environ.get("ANDROID_JAR_PATH")
    if android_jar_path is None:
        platform_name = platform.system()
        if platform_name == "Linux":
            android_jar_path = "/usr/lib/android-sdk/platforms/"
        elif platform_name == "Windows":
            android_jar_path = "C:\\Program Files\\Android\\android-sdk\\platforms\\"
        elif platform_name == "Darwin":
            android_jar_path = f"/Users/{os.environ.get('USER')}/Library/Android/sdk/platforms/"

    jar_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "SootAndro-2.8.jar")

    if not exists(os.path.join('.', 'SOOTOUT', os.path.basename(apk_path).replace('.apk', ''))):
        java_command = sh_split(f'java -jar {jar_file} {package} {apk_path} {android_jar_path}')
        try:
            subprocess.run(java_command, timeout=1000)
        except:
            pass
    if exists(os.path.join('.', 'SOOTOUT', os.path.basename(apk_path).replace('.apk', ''))):
        apk_info_path = os.path.join('.', 'SOOTOUT', os.path.basename(apk_path).replace('.apk', ''),
                                         'apk_info_file.pkl')
        apk_info_file = open(apk_info_path, 'wb')
        pickle.dump(apkInfo(exported_activities, receivers, activities, package), apk_info_file)
        apk_info_file.close()
        return True, package
    print('No SOOT output')
    return False, package

if __name__ == "__main__":
    start_static_analysis("/Users/andreronda/Documents/HybridAnalysis/apps/UnhandledException-DOS-Lean.apk")
