import os
import numpy
from gym import spaces
from stable_baselines3 import SAC
from stable_baselines3.sac.policies import MlpPolicy
from dynamic_analysis.utils.TimerCallback import TimerCallback
from dynamic_analysis.utils.wrapper import TimeFeatureWrapper


class SACAlgorithm():
    @staticmethod
    def explore(ICC_Env, timesteps, timer, train_freq=5, target_update_interval=10, **kwargs):

        # env = TimeFeatureWrapper(ICC_Env)
        env = ICC_Env
        # Loading a previous policy and checking file existence
        model = SAC(MlpPolicy, env, verbose=1, train_freq=train_freq, target_update_interval=target_update_interval,
                    learning_rate=0.0006)
        model.env.envs[0].app_env.check_activity()
        callback = TimerCallback(timer=timer, env=env)
        model.learn(total_timesteps=timesteps, callback=callback)

        '''
        except Exception as e:
            print(e)
            appium.restart_appium()
            if emulator is not None:
                emulator.restart_emulator()
            return False
        '''
