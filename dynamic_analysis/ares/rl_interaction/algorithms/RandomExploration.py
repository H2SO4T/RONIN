from dynamic_analysis.ares.rl_interaction.algorithms.ExplorationAlgorithm import ExplorationAlgorithm
from dynamic_analysis.ares.rl_interaction.utils.utils import Timer


class RandomAlgorithm(ExplorationAlgorithm):

    @staticmethod
    def explore(app, emulator, appium, timesteps, timer, **kwargs):
        try:
            app.reset()
            t = Timer(timer)
            while not t.timer_expired():
                action = app.action_space.sample()
                o, _, done, _ = app.step(action)
                app.coverage_count += 1
                if (app.timesteps % 25) == 0 and app.instr:
                    try:
                        app.instr_funct(udid=app.udid, package=app.package, coverage_dir=app.coverage_dir,
                                        coverage_count=app.coverage_count)
                    except Exception as e:
                        print(e)
                if done:
                    app.reset()
            return True
        except Exception as e:
            appium.restart_appium()
            if emulator is not None:
                emulator.restart_emulator()
            return False
