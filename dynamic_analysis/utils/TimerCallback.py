import os
import time
from stable_baselines3.common.callbacks import BaseCallback
from dynamic_analysis.utils.timer import Timer
from loguru import logger


class TimerCallback(BaseCallback):
    def __init__(self, timer, env, verbose=0):
        super(TimerCallback, self).__init__(verbose)
        self.timer = Timer(timer)
        self.env = env

    def _on_training_start(self) -> None:
        """
        This method is called before the first rollout starts.
        """
        pass

    def _on_rollout_start(self) -> None:
        """
        A rollout is the collection of environment interaction
        using the current policy.
        This event is triggered before collecting new samples.
        """
        pass

    '''
        elif self.env.stop_execution:
        self.env.stop_execution = False
        print("Vulnerability triggered")
        logger.info(f'Vulnerability found, execution stopped')
        return False
    '''

    def _on_step(self) -> bool:
        """
        This method will be called by the model after each call to `env.step()`.

        For child callback (of an `EventCallback`), this will be called
        when the event is triggered.

        :return: (bool) If the callback returns False, training is aborted early.
        """
        if self.timer.timer_expired():
            logger.info(f'Timer expired at {self.num_timesteps}')
            return False
        else:
            return True

    def _on_rollout_end(self) -> None:
        """
        This event is triggered before updating the policy.
        """
        pass

    def _on_training_end(self) -> None:
        """
        This event is triggered before exiting the `learn()` method.
        """
        pass
