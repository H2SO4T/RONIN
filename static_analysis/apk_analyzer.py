from androguard.core.bytecodes import apk

def analyze(apk_path):
    string_activities = '*'
    a = apk.APK(apk_path)
    activities, services, receivers, providers = find_exported_components(a)
    androguard_activities = a.get_activities()
    exported_activities = list()
    for activity in androguard_activities:
        activity = activity.replace("..", ".")
        for act in activities:
            if act['activity'] in activity:
                exported_activities.append({'activity': activity, 'actions': act['actions']})
    return exported_activities, services, receivers, providers, activities, a.package


def find_exported_components(apk):
    activities = list()
    services = list()
    receivers = list()
    providers = list()
    for tag in [
        "activity",
        "activity-alias",
        "service",
        "receiver",
        "provider",
    ]:
        for item in apk.find_tags(tag):
            actions = list()
            name = item.get(apk._ns("name"), "")
            exported = item.get(apk._ns("exported"), "")
            permission = item.get(apk._ns("permission"), "")

            # Check only components where the exported attribute is not set to
            # false explicitly.
            if name.strip() and exported.lower() != "false":
                to_check = False
                has_actions_in_intent_filter = False
                for intent in item.findall("./intent-filter"):
                    for action in intent.findall("./action"):
                        my_action = action.get(apk._ns("name"), "")
                        actions.append(my_action)
                        has_actions_in_intent_filter = True

                # Exported attribute is not set explicitly, but the component
                # has intent filters (so the component is exported).
                if exported == "" and has_actions_in_intent_filter:
                    to_check = True

                # Exported attribute is set to True explicitly.
                if exported.lower() == "true":
                    to_check = True

                if to_check:
                    accessible = False
                    if not permission:
                        # Exported, without any permission set.
                        accessible = True
                    else:
                        # Exported, with permission set.
                        detail = apk.get_declared_permissions_details().get(
                            permission
                        )
                        if detail:
                            level = detail["protectionLevel"]
                            if level == "None":
                                level = None
                            if (
                                    level
                                    and (
                                            int(level, 16) == 0x0
                                            or int(level, 16) == 0x1
                                    )
                            ) or not level:
                                # 0x0 is normal protectionLevel,
                                # 0x1 is dangerous protectionLevel
                                # (protectionLevel is set to normal by
                                # default).
                                accessible = True
                        else:
                            detail = apk.get_details_permissions().get(
                                permission
                            )
                            if detail:
                                level = detail[0].lower()
                                if level == "normal" or level == "dangerous":
                                    accessible = True
                    if accessible:
                        if (tag == "activity") or (tag == "activity-alias"):
                            activities.append({'activity': name, 'actions': actions})
                        elif tag == "service":
                            services.append({'type': 'service', 'name': name, 'actions': actions})
                        elif tag == "receiver":
                            receivers.append({'type': 'receiver', 'name': name, 'actions': actions})
                        elif tag == "provider":
                            providers.append({'type': 'provider', 'name': name, 'actions': actions})
    return activities, services, receivers, providers
