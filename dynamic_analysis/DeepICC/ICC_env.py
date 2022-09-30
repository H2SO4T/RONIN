import os

import time
import ast
import subprocess
import numpy as np
from gym import Env
from gym import spaces
import networkx
from multiprocessing import Process, Queue


def logcat_listener(logcat_queue, bug_queue, udid):
    os.system(f'adb -s {udid} logcat -c')
    proc = subprocess.Popen(['adb', '-s', udid, 'logcat'], stdout=subprocess.PIPE)
    while True:
        dump_bug = ''
        try:
            temp = proc.stdout.readline().decode('utf-8')
        except UnicodeDecodeError as e:
            print(e)
        if temp.find('{\'method\':') > 0:
            logcat_queue.put(temp[temp.index('{'):temp.index('}') + 1])
        if temp.find('FATAL EXCEPTION') > 0:
            dump_bug += temp[temp.find('FATAL EXCEPTION'):]
            try:
                temp = proc.stdout.readline().decode('utf-8')
            except UnicodeDecodeError:
                temp = ''
            while temp.find('E AndroidRuntime:') > 0:
                dump_bug += temp[temp.find('E AndroidRuntime:'):]
                temp = proc.stdout.readline().decode('utf-8')
            bug_queue.put(dump_bug)


class ICCEnv(Env):
    def __init__(self, app_env, vulnerability, dot_file, intent_target: str, type_intent: str, intent_action: str,
                 extra_parameters: dict, list_activities: list,
                 udid: str, vulnerability_type: str = 'IDOS'):
        super(ICCEnv, self).__init__()

        self.app_env = app_env
        self.previous_distance = 1_000_000
        self.vulnerability = vulnerability
        self.dot_file = dot_file
        self.vulnerability_type = vulnerability_type
        self.intent_target = intent_target
        self.intent_action = intent_action
        self.command_string = ''
        self.udid = udid
        self.timesteps = 0
        self.extra_parameters = extra_parameters
        self.number_extras = len(extra_parameters.keys())
        self.extra_key_list = list(extra_parameters.keys())
        self.potentially_not_a_vulnerability = False
        self.target_node = None
        self.stop_execution = False
        for node in self.dot_file.nodes:
            if node == '\\n':
                continue
            method, stmt = node.split('|')
            method = method.replace('-', '"').strip()
            stmt = stmt.replace('-', '"').strip()
            if vulnerability['method'].find(method) >= 0 and vulnerability['stmt'].find(stmt) >= 0:
                self.target_node = node
        self.type_intent = type_intent
        self.logcat_queue = Queue()
        self.bug_queue = Queue()
        self.bug_proc_pid = self.start_logcat_listener()
        self.true_positives = list()

        # # ACTIONS # #
        # An action comprises:
        # - a broadcast/activity
        # - an action (if available)
        # - the extras
        # A generated intent must always contain:
        # - a broadcast/activity
        # - an action
        # NOTE: we need to trigger one broadcast/activity at time

        # IMPLEMENTATION:
        # Default intent: start intent <broadcast/activity> -action <action> <void_extra> <void_extra> ...
        # ! the intent is represented as a list of parameters (each extra has a fixed position within the list)
        # the algorithm can generate numbers to modify this intent
        # e.g. : [0-1 <- {(1):add/modify; (0):remove}  , 0-num <- which extra , 0-num <- with which value]
        # the first dimension
        # the second dimension indicates which extra we want to add/modify or remove (we infer the type subsequently)
        # the third dimension indicates which value we want to use

        # # OBSERVATION # #
        # The observation is collected directly from the logcat thanks to the instrumented app, we compare the nodes
        # of the taint graph with what we find within logcat, we look at a target at time, and we compute the distance
        # Add the activity position
        # between where we arrived and where we want to arrive

        # # REWARD # #
        # The reward is given with respect to the last execution, if we decreased the distance from the target,
        # we are happy, otherwise we give zero reward.
        self.count_intent_actions = 0
        self.prefix = ''
        if self.type_intent == 'broadcast':
            self.prefix = f'adb shell am broadcast -n {self.intent_target} '
            if self.intent_action != '':
                self.prefix += f' -a {self.intent_action}'
            # TODO now we need to launch the app
        else:
            # in this case we don't
            self.prefix = f'adb shell am start -n {self.intent_target} '

        index = self.prefix.rfind('.')
        self.prefix = self.prefix[:index] + '/.' + self.prefix[index + 1:]

        self.prefix = self.prefix.replace('//', '/')

        # we add the action if available

        if self.intent_action != '':
            self.prefix += f' -a {self.intent_action}'

        self.intent_vector = [None] * self.number_extras

        self.list_activities = self.app_env.one_hot_encoding_activities()

        self.observation = np.array([0] * len(self.list_activities) + [0] * len(self.dot_file.nodes))

        self.N_OBSERVATIONS = len(self.observation)
        self.action_space = spaces.MultiDiscrete([2, self.number_extras, 5])
        self.observation_space = spaces.Box(low=0, high=10, shape=(self.N_OBSERVATIONS,), dtype=np.int64)

    def get_execution_trace(self):
        execution_trace = []
        while not self.logcat_queue.empty():
            execution_trace.append(ast.literal_eval(self.logcat_queue.get()))
        return execution_trace

    def compute_reward(self, distance):
        if distance != None:
            if distance == 0:
                self.previous_distance = distance
                return 10, True
            elif distance - self.previous_distance > 0:
                self.previous_distance = distance
                return -1, False
            elif distance - self.previous_distance == 0:
                self.previous_distance = distance
                return 0, False
            elif distance - self.previous_distance < 0:
                self.previous_distance = distance
                return 1, False
        else:
            return -10, False

    def step(self, action):
        self.timesteps += 1
        self.count_intent_actions += 1
        # self.app_env.driver.current_activity
        action = action.astype(int)
        if action[0] < self.action_space.nvec[0] and action[1] < self.action_space.nvec[1] \
                and action[2] < len(self.extra_parameters[self.extra_key_list[action[1]]]):
            if action[0] == 0:
                # remove extra value
                self.intent_vector[action[1]] = None
            else:
                # add extra value
                self.intent_vector[action[1]] = self.extra_parameters[self.extra_key_list[action[1]]][action[2]]
            self.command_string = ''
            for i in range(self.number_extras):
                if self.intent_vector[i] is not None and self.intent_vector[i] != '':
                    self.command_string += f' {self.extra_key_list[i]} {self.intent_vector[i]}'
            # wait for intent execution
            self.command_string = f'{self.prefix} {self.command_string}'
            print(self.command_string.replace('$', ''))
            os.system(self.command_string.replace('$', ''))
            time.sleep(1)
            return self.get_observation()
        else:
            return self.observation, np.array([-10]), np.array(False), {}

    def get_observation(self):
        reward = -1
        done = False
        activity_observation = self.app_env.one_hot_encoding_activities()
        if (self.logcat_queue.empty() and self.bug_queue.empty()) or self.count_intent_actions == 5:
            self.count_intent_actions = 0
            # we start the app exploration
            for i in range(3):
                self.app_env.update_views()
                try:
                    o, _, done, _ = self.app_env.step(self.app_env.action_space.sample())
                except:
                    pass
                if not self.logcat_queue.empty() or not self.bug_queue.empty() or done:
                    break
        execution_trace = self.get_execution_trace()

        if len(execution_trace) > 0 and self.bug_queue.empty():
            observation, distance = self.compute_distance(execution_trace)
            reward, done = self.compute_reward(distance)
            if done and self.vulnerability_type == 'IDOS':
                self.potentially_not_a_vulnerability = True
                self.observation = np.concatenate((observation, np.array(activity_observation)))
            return self.observation, np.array([reward]), np.array(done), {}

        if len(execution_trace) == 0 and not self.bug_queue.empty():
            self.store_intent(execution_trace)
            return self.observation, np.array([10]), np.array(True), {}

        if len(execution_trace) > 0 and not self.bug_queue.empty():
            observation, distance = self.compute_distance(execution_trace)
            self.observation = np.concatenate((observation, np.array(activity_observation)))
            self.store_intent(execution_trace)
            return self.observation, np.array([10]), np.array(True), {}

        if len(execution_trace) == 0 and self.bug_queue.empty():
            return np.concatenate(([0] * len(self.dot_file.nodes), np.array(activity_observation))), np.array(
                [reward]), np.array(done), {}

    def compute_distance(self, execution_trace):
        last_node = execution_trace[-1]
        distance = None
        for node in self.dot_file.nodes:
            if node == '\\n':
                continue
            method, stmt = node.split('|')
            method = method.replace('-', '"').strip()
            stmt = stmt.replace('-', '"').strip()
            if last_node['method'] in method and last_node['unit'] in stmt:
                try:
                    distance = networkx.shortest_path_length(self.dot_file, node, self.target_node)
                except Exception as e:
                    distance = -1

        # observation
        observation = [0] * len(self.dot_file.nodes)
        i = 0
        for node in self.dot_file.nodes:
            if node == '\\n':
                continue
            method, stmt = node.split('|')
            method = method.replace('-', '"').strip()
            stmt = stmt.replace('-', '"').strip()
            for my_node in execution_trace:
                if my_node['method'] in method and my_node['unit'] in stmt:
                    observation[i] = 1
            i += 1
        return observation, distance

    def reset(self):
        self.app_env.reset()
        self.count_intent_actions = 0
        self.observation = np.array([0] * len(self.list_activities) + [0] * len(self.dot_file.nodes))
        return self.observation

    def start_logcat_listener(self):
        logcat_process = Process(name='logcat_listener', target=logcat_listener, args=(self.logcat_queue,
                                                                                       self.bug_queue, self.udid))
        logcat_process.daemon = True
        logcat_process.start()
        return logcat_process.pid

    def store_intent(self, execution_trace):
        self.true_positives.append(
            {'vulnerability_confirmed': self.vulnerability, 'execution_path': execution_trace,
             'intent': self.command_string,
             'bug_log': self.bug_queue.get(), 'timesteps': self.timesteps})
