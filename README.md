# RONIN

# Requirements

* Android emulator or Android smartphone
* MacOS or Ubuntu or Windows
* Python 3.7+
* Android command line tools installed and functioning from terminal

# Installation and Setup

* Install Appium from http://appium.io/docs/en/about-appium/getting-started/; please make sure to set up the 
  environment variables. $ANDROID_HOME and $JAVA_HOME
* Use appium-doctor to check that everything is working correctly
* Create a virtualenv named `venv` in folder ARES (not in rl_interaction):
`virtualenv -p python3 venv` and source it `source venv/bin/activate`
* Install the requirements `requirements.txt` using the command `pip3 install -r requirements.txt`
* Modify the `dynamic_analysis/config.ini` file and modify the file accordingly to your configuration, some of them:
  * `udid`
  * `android_v`
  * `device_name`
  * `pool_strings`

# Using RONIN

* Export PYTHONPATH: ``export PYTHONPATH="path/to/RONIN"``
* Generate a folder for the apks, and put them inside
* Activate the venv 
* Launch the command

``python3 main.py --apk_folder /path/to/folder ``


# Output

RONIN generates a folder named ``SOOTOUT`` that contains the output of the `static_anaysis` 
an eventually of the `dynamic_analysis`

