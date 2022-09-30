import argparse
import glob
import os
import shutil
from dynamic_analysis import dynamic_analysis
from static_analysis import static_analysis_manager


def lets_go():
    parser = argparse.ArgumentParser(description='Give me the apks folder')
    parser.add_argument('--apk_folder', type=str, required=True)
    parser.add_argument('--iterations', type=int, default=1_000_000)
    args = parser.parse_args()
    apk_folder = args.apk_folder
    apps = glob.glob(f'{apk_folder}{os.sep}*.apk')

    error_folder_name = 'error_folder'
    os.makedirs(os.path.join(os.path.dirname(__file__), error_folder_name), exist_ok=True)

    analyzed_folder_name = 'analyzed_folder'
    os.makedirs(os.path.join(os.path.dirname(__file__), analyzed_folder_name), exist_ok=True)
    for app in apps:
        print(f'starting static analysis of: {app}')
        result, package = static_analysis_manager.start_static_analysis(apk_path=os.path.abspath(app))
        if result:
            app_name = os.path.basename(app).replace('.apk', '')
            app_path = os.path.join(os.getcwd(), 'SOOTOUT', app_name)
            print(f'starting dynamic analysis of {app}')
            try:
                dynamic_analysis.start_dynamic_analysis(app_path=app_path, app_name=app_name)
                shutil.move(os.path.abspath(app),
                            os.path.join(os.path.dirname(__file__), analyzed_folder_name, os.path.basename(app)))
            except Exception as e:
                os.system('adb emu kill')
                app_name = app.replace('.apk', '').replace(f'{apk_folder}/', '')
                with open(os.path.join(os.path.dirname(__file__), error_folder_name, f'{app_name}.txt'), 'a') as f:
                    f.write(str(e))
                shutil.move(os.path.abspath(app),
                            os.path.join(os.path.dirname(__file__), error_folder_name, os.path.basename(app)))
            os.system(f"adb uninstall {package}")
        else:
            shutil.move(os.path.abspath(app),
                        os.path.join(os.path.dirname(__file__), analyzed_folder_name, os.path.basename(app)))


if __name__ == '__main__':
    lets_go()
