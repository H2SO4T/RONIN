from jsonic import Serializable


class apkInfo(Serializable):
    def __init__(self, exported_activities: list, receivers: list, activities: list, package: str):
        super().__init__()
        self.exported_activities = exported_activities
        self.receivers = receivers
        self.activities = activities
        self.package = package