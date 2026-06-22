import argparse
import requests
import json
import time
import copy
import threading
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from config import vdom_policy_template

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

VDOM_LINK_0_IP = "10.10.10.1"
VDOM_LINK_1_IP = "10.10.10.2"
VDOM_LINK_PREFIX = "T-"
POLICY_PREFIX = "T-"
STATIC_ROUTE_PREFIX = "T-"
snmp_modified = []
modified_community_ids = []
LOG_DISK_VDOM1_STATUS = ""
LOG_DISK_VDOM2_STATUS = ""
LOG_DISK_VDOM_ROOT_STATUS = ""
LOG_MEM_VDOM1_STATUS = ""
LOG_MEM_VDOM2_STATUS = ""
LOG_MEM_VDOM_ROOT_STATUS = ""
LOG_DISK_LOCAL_REPORTS_VDOM_ROOT_STATUS = ""
LOG_DISK_LOCAL_REPORTS_VDOM1_STATUS = ""
LOG_DISK_LOCAL_REPORTS_VDOM2_STATUS = ""
LOG_DISK_FORTIVIEW_VDOM_ROOT_STATUS = ""
LOG_DISK_FORTIVIEW_VDOM1_STATUS = ""
LOG_DISK_FORTIVIEW_VDOM2_STATUS = ""

EVENT_TYPES_TO_CONTROL = [
        # "event",
        "system",
        # "vpn",
        # "user",
        # "router",
        # "endpoint",
        # "rest-api"
]
SYSTEM_EVENT_ROOT_STATUS = {}
SYSTEM_EVENT_VDOM1_STATUS = {}
SYSTEM_EVENT_VDOM2_STATUS = {}
SYSLOGD_ORIGINAL_STATUS = ""

def login_to_fortigate(ip, username, password, verify_ssl=False):
    login_url = f"https://{ip}/logincheck"
    
    try:
        session = requests.Session()
        session.verify = verify_ssl
        
        response = session.post(
            login_url,
            data={"username": username, "secretkey": password},
            timeout=10
        )
        
        if response.status_code == 200 and "redir" in response.text:
            csrf_token = None
            for cookie in response.cookies:
                if "ccsrftoken" in cookie.name:
                    csrf_token = cookie.value.strip('"')
                    break
            
            if csrf_token:
                return session, csrf_token
            else:
                print("not found CSRF token in cookies")
        else:
            print(f"logon failed: HTTP {response.status_code}")
            print(f"response: {response.text[:200]}...")
    
    except requests.exceptions.RequestException as e:
        print(f"network error: {e}")
    except Exception as e:
        print(f"unexpected error: {e}")
    
    return None, None

def logout_from_fortigate(ip, session, csrf_token):
    logout_url = f"https://{ip}/logout"
    
    try:
        response = session.get(
            logout_url,
            headers={"X-CSRFTOKEN": csrf_token},
            timeout=10
        )
        
        if response.status_code == 200:
            print("logout successful.")
            return True
        else:
            print(f"logout failed: HTTP {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"logout network error: {e}")
        return False
    except Exception as e:
        print(f"logout unexpected error: {e}")
        return False

def get_vdom_list(ip, session, csrf_token):
    url = f"https://{ip}/api/v2/cmdb/system/vdom"
    
    try:
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token})
        if response.status_code == 200:
            vdoms = response.json().get("results", [])
            return [vdom["name"] for vdom in vdoms]
        else:
            print(f"get vdom list failed: HTTP {response.status_code}")
            return []
    except Exception as e:
        print(f"get vdom list error: {e}")
        return []

def disable_config_log_disk_setting(ip, session, csrf_token, vdom1, vdom2):
    global LOG_DISK_VDOM1_STATUS, LOG_DISK_VDOM2_STATUS, LOG_DISK_VDOM_ROOT_STATUS
    global LOG_DISK_LOCAL_REPORTS_VDOM1_STATUS, LOG_DISK_LOCAL_REPORTS_VDOM2_STATUS, LOG_DISK_LOCAL_REPORTS_VDOM_ROOT_STATUS
    global LOG_DISK_FORTIVIEW_VDOM1_STATUS, LOG_DISK_FORTIVIEW_VDOM2_STATUS, LOG_DISK_FORTIVIEW_VDOM_ROOT_STATUS

    url = f"https://{ip}/api/v2/cmdb/report/setting"
    try:
        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": "root"
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            report_status = results.get("pdf-report", "")
            fortiview_status = results.get("fortiview", "")
            LOG_DISK_LOCAL_REPORTS_VDOM_ROOT_STATUS = report_status
            LOG_DISK_FORTIVIEW_VDOM_ROOT_STATUS = fortiview_status
            print(f"root-local-reports status: {report_status}")
            print(f"root-fortiview status: {fortiview_status}")

        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": vdom1
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            report_status = results.get("pdf-report", "")
            fortiview_status = results.get("fortiview", "")
            LOG_DISK_LOCAL_REPORTS_VDOM1_STATUS = report_status
            LOG_DISK_FORTIVIEW_VDOM1_STATUS = fortiview_status
            print(f"root-local-reports status: {report_status}")
            print(f"root-fortiview status: {fortiview_status}")

        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": vdom2
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            report_status = results.get("pdf-report", "")
            fortiview_status = results.get("fortiview", "")
            LOG_DISK_LOCAL_REPORTS_VDOM2_STATUS = report_status
            LOG_DISK_FORTIVIEW_VDOM2_STATUS = fortiview_status
            print(f"{vdom2}-local-reports status: {report_status}")
            print(f"{vdom2}-fortiview status: {fortiview_status}")
            
    except Exception as e:
        print(f"get root/{vdom1}/{vdom2}local report setting failed: {e}")
        return False

    url = f"https://{ip}/api/v2/cmdb/log.disk/setting"
    vdom1_ok = False
    vdom2_ok = False
    vdom_root = False
    try:
        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": "root"
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            status = results.get("status", "")
            LOG_DISK_VDOM_ROOT_STATUS = status
            print(f"root-disk log status: {status}")
            if status == "enable":
                disbale_config = copy.deepcopy(results)
                disbale_config.update({"status": "disable"})
                response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=disbale_config)
                if response.status_code == 200:
                    vdom_root = True
                    print(f"root-disk log disabled successfully")
            elif status == "disable":
                print("root-disk log does not need to be disabled")
                vdom_root = True

        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": vdom1
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            status = results.get("status", "")
            print(f"{vdom1}-disk log status: {status}")
            LOG_DISK_VDOM1_STATUS = status
            if status == "enable":
                disbale_config = copy.deepcopy(results)
                disbale_config.update({"status": "disable"})
                response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=disbale_config)
                if response.status_code == 200:
                    vdom1_ok = True
                    print(f"{vdom1} disk log disabled successfully")
            elif status == "disable":
                print(f"{vdom1} disk log does not need to be disabled")
                vdom1_ok = True

        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": vdom2
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            status = results.get("status", "")
            print(f"{vdom2}-disk log status: {status}")
            LOG_DISK_VDOM2_STATUS = status
            if status == "enable":
                disbale_config = copy.deepcopy(results)
                disbale_config.update({"status": "disable"})
                response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=disbale_config)
                if response.status_code == 200:
                    vdom2_ok = True
                    print(f"{vdom2} disk log disabled successfully")
            elif status == "disable":
                print(f"{vdom2} disk log does not need to be disabled")
                vdom2_ok = True

    except Exception as e:
        print(f"root/{vdom1}/{vdom2} disk log setting failed: {e}")
        return False

    if vdom1_ok and vdom2_ok and vdom_root:
        return True
    else:
        return False

def disable_config_log_memory_setting(ip, session, csrf_token, vdom1, vdom2):
    global LOG_MEM_VDOM_ROOT_STATUS, LOG_MEM_VDOM1_STATUS, LOG_MEM_VDOM2_STATUS
    url = f"https://{ip}/api/v2/cmdb/log.memory/setting"
    vdom1_ok = False
    vdom2_ok = False
    vdom_root = False
    try:

        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": "root"
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            status = results.get("status", "")
            print(f"root-memory log status: {status}")
            LOG_MEM_VDOM_ROOT_STATUS = status
            if status == "enable":
                disbale_config = copy.deepcopy(results)
                disbale_config.update({"status": "disable"})
                response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=disbale_config)
                if response.status_code == 200:
                    vdom_root = True
                    print(f"root log-memory disable success")
            elif status == "disable":
                print("root log-memory no need to disable")
                vdom_root = True

        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": vdom1
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            status = results.get("status", "")
            print(f"{vdom1}-memory log status: {status}")
            LOG_MEM_VDOM1_STATUS = status
            if status == "enable":
                disbale_config = copy.deepcopy(results)
                disbale_config.update({"status": "disable"})
                response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=disbale_config)
                if response.status_code == 200:
                    vdom1_ok = True
                    print(f"{vdom1} log-memory disable success")
            elif status == "disable":
                print(f"{vdom1} log-memory no need to disable")
                vdom1_ok = True
        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": vdom2
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            status = results.get("status", "")
            print(f"{vdom2}-memory log status: {status}")
            LOG_MEM_VDOM2_STATUS = status
            if status == "enable":
                disbale_config = copy.deepcopy(results)
                disbale_config.update({"status": "disable"})
                response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=disbale_config)
                if response.status_code == 200:
                    vdom2_ok = True
                    print(f"{vdom2} log-memory disable success")
            elif status == "disable":
                print(f"{vdom2} log-memory no need to disable")
                vdom2_ok = True
        if vdom1_ok and vdom2_ok and vdom_root:
            return True
        else:
            return False
    except Exception as e:
        print(f"root/{vdom1}/{vdom2}log-memory setting failed")
        return False

def enable_config_log_disk_setting(ip, session, csrf_token, vdom1, vdom2):
    
    url = f"https://{ip}/api/v2/cmdb/report/setting"
    try:
        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": "root"
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            report_status = results.get("pdf-report", "")
            fortiview_status = results.get("fortiview", "")
            report_config = copy.deepcopy(results)
            if LOG_DISK_LOCAL_REPORTS_VDOM_ROOT_STATUS != report_status:
                report_config.update({"pdf-report": LOG_DISK_LOCAL_REPORTS_VDOM_ROOT_STATUS})
            else:
                print("root-local-reports log no need to restore")
            if LOG_DISK_FORTIVIEW_VDOM_ROOT_STATUS != fortiview_status:
                report_config.update({"fortiview": LOG_DISK_FORTIVIEW_VDOM_ROOT_STATUS})
            else:
                print("root-fortiview log no need to restore")
            response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=report_config)
            if response.status_code == 200:
                print(f"root-local-reports/fortiview setting restored successfully")


        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": vdom1
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            report_status = results.get("pdf-report", "")
            fortiview_status = results.get("fortiview", "")
            report_config = copy.deepcopy(results)
            if LOG_DISK_LOCAL_REPORTS_VDOM1_STATUS != report_status:
                report_config.update({"pdf-report": LOG_DISK_LOCAL_REPORTS_VDOM1_STATUS})                
            else:
                print(f"{vdom1}-local-reports log no need to restore")
            if LOG_DISK_FORTIVIEW_VDOM1_STATUS != fortiview_status:
                report_config.update({"fortiview": LOG_DISK_FORTIVIEW_VDOM1_STATUS})
            else:
                print(f"{vdom1}-fortiview log no need to restore")
            response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=report_config)
            if response.status_code == 200:
                print(f"{vdom1}-local-reports log restored successfully")
            
        params = {
            "datasource": "true",
            "with_meta": "true",
            "vdom": vdom2
        }
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            report_status = results.get("pdf-report", "")
            fortiview_status = results.get("fortiview", "")
            report_config = copy.deepcopy(results)
            if LOG_DISK_LOCAL_REPORTS_VDOM2_STATUS != report_status:
                report_config.update({"pdf-report": LOG_DISK_LOCAL_REPORTS_VDOM2_STATUS})     
            else:
                print(f"{vdom2}-local-reports log no need to restore")
                
            if LOG_DISK_FORTIVIEW_VDOM2_STATUS != fortiview_status:
                report_config.update({"fortiview": LOG_DISK_FORTIVIEW_VDOM2_STATUS})
            else:
                print(f"{vdom2}-fortiview log no need to restore")
            response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=report_config)
            if response.status_code == 200:
                print(f"{vdom2}-local-reports log restored successfully")

    except Exception as e:
        print(f"root/{vdom1}/{vdom2}local-reports/fortiview setting failed")
        return False

    url = f"https://{ip}/api/v2/cmdb/log.disk/setting"
    vdom1_ok = False
    vdom2_ok = False
    vdom_root = False
    
    try:
        print(f"root-disk status: {LOG_DISK_VDOM_ROOT_STATUS}")
        if LOG_DISK_VDOM_ROOT_STATUS == "enable":
            params = {
                "datasource": "true",
                "with_meta": "true",
                "vdom": "root"
            }
            response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
            if response.status_code == 200:
                results = response.json().get("results", {})
                status = results.get("status", "")
                print(f"root-disk log status: {status}")
                if status == "disable":
                    enable_config = copy.deepcopy(results)
                    enable_config.update({"status": "enable"})
                    response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=enable_config)
                    if response.status_code == 200:
                        vdom_root = True
                        print(f"root log enable success")
        elif LOG_DISK_VDOM_ROOT_STATUS == "disable":
            print("root log no need to enable")
            vdom_root = True
    
        print(f"root-vdom1 status: {LOG_DISK_VDOM1_STATUS}")
        if LOG_DISK_VDOM1_STATUS == "enable":
            params = {
                "datasource": "true",
                "with_meta": "true",
                "vdom": vdom1
            }
            response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
            if response.status_code == 200:
                results = response.json().get("results", {})
                status = results.get("status", "")
                print(f"{vdom1}-disk log status: {status}")
                if status == "disable":
                    enable_config = copy.deepcopy(results)
                    enable_config.update({"status": "enable"})
                    response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=enable_config)
                    if response.status_code == 200:
                        vdom1_ok = True
                        print(f"{vdom1} log enable success")
        elif LOG_DISK_VDOM1_STATUS == "disable":
            print(f"{vdom1} log no need to enable")
            vdom1_ok = True

        print(f"root-vdom2 status: {LOG_DISK_VDOM2_STATUS}")
        if LOG_DISK_VDOM2_STATUS == "enable":
            params = {
                "datasource": "true",
                "with_meta": "true",
                "vdom": vdom2
            }
            response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
            if response.status_code == 200:
                results = response.json().get("results", {})
                status = results.get("status", "")
                print(f"{vdom2}-disk log status: {status}")
                if status == "disable":
                    enable_config = copy.deepcopy(results)
                    enable_config.update({"status": "enable"})
                    response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=enable_config)
                    if response.status_code == 200:
                        vdom2_ok = True
                        print(f"{vdom2} log enable success")
        elif LOG_DISK_VDOM2_STATUS == "disable":
            print(f"{vdom2} log no need to enable")
            vdom2_ok = True

    except Exception as e:
        print(f"root/{vdom1}/{vdom2} log-disk setting failed")
        return False
    
    if vdom1_ok and vdom2_ok and vdom_root:
        return True
    else:
        return False

def enable_config_log_memory_setting(ip, session, csrf_token, vdom1, vdom2):
    url = f"https://{ip}/api/v2/cmdb/log.memory/setting"
    vdom1_ok = False
    vdom2_ok = False
    vdom_root = False
    try:
        print(f"root-memory status: {LOG_MEM_VDOM_ROOT_STATUS}")
        if LOG_MEM_VDOM_ROOT_STATUS == "enable":
            params = {
                "datasource": "true",
                "with_meta": "true",
                "vdom": "root"
            }
            response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
            if response.status_code == 200:
                results = response.json().get("results", {})
                status = results.get("status", "")
                if status == "disable":
                    enable_config = copy.deepcopy(results)
                    enable_config.update({"status": "enable"})
                    response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=enable_config)
                    if response.status_code == 200:
                        vdom_root = True
                        print(f"root log-memory enable success")
        elif LOG_MEM_VDOM_ROOT_STATUS == "disable":
            print("root log-memory no need to enable")
            vdom_root = True
        
        print(f"vdom1-memory status: {LOG_MEM_VDOM1_STATUS}")
        if LOG_MEM_VDOM1_STATUS == "enable":
            params = {
                "datasource": "true",
                "with_meta": "true",
                "vdom": vdom1
            }
            response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
            if response.status_code == 200:
                results = response.json().get("results", {})
                status = results.get("status", "")
                if status == "disable":
                    enable_config = copy.deepcopy(results)
                    enable_config.update({"status": "enable"})
                    response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=enable_config)
                    if response.status_code == 200:
                        vdom1_ok = True
                        print(f"{vdom1} log-memory enable success")
        elif LOG_MEM_VDOM1_STATUS == "disable":
            print(f"{vdom1} log-memory no need to enable")
            vdom1_ok = True
        
        print(f"vdom2-memory status: {LOG_MEM_VDOM2_STATUS}")
        if LOG_MEM_VDOM2_STATUS == "enable":
            params = {
                "datasource": "true",
                "with_meta": "true",
                "vdom": vdom2
            }
            response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
            if response.status_code == 200:
                results = response.json().get("results", {})
                status = results.get("status", "")
                if status == "disable":
                    enable_config = copy.deepcopy(results)
                    enable_config.update({"status": "enable"})
                    response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=enable_config)
                    if response.status_code == 200:
                        vdom2_ok = True
                        print(f"{vdom2} log-memory enable success")
        elif LOG_MEM_VDOM2_STATUS == "disable":
            print(f"{vdom2} log-memory no need to enable")
            vdom2_ok = True

        if vdom1_ok and vdom2_ok and vdom_root:
            return True
        else:
            return False
    except Exception as e:
        print(f"root/{vdom1}/{vdom2} log-memory setting failed")
        return False

def disable_system_events_setting(ip, session, csrf_token, vdom1, vdom2):
    global SYSTEM_EVENT_ROOT_STATUS, SYSTEM_EVENT_VDOM1_STATUS, SYSTEM_EVENT_VDOM2_STATUS
    url = f"https://{ip}/api/v2/cmdb/log/eventfilter"
    vdom_root_ok = False
    vdom1_ok = False
    vdom2_ok = False

    def _disable_vdom_events(vdom_name):
        params = {"datasource": "true", "with_meta": "true", "vdom": vdom_name}
        get_response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if get_response.status_code != 200:
            print(f"[{vdom_name}] get log eventfilter config failed, HTTP {get_response.status_code}")
            return False, {}

        get_data = get_response.json()
        current_config = get_data.get("results", {})

        if not isinstance(current_config, dict):
            print(f"[{vdom_name}] unexpected results type: {type(current_config)}")
            return False, {}

        # print(f"[{vdom_name}] GET current config: {json.dumps(current_config, indent=2, ensure_ascii=False)}")

        original_status = {}
        disable_config = copy.deepcopy(current_config)
        has_enable = False

        for event_type in EVENT_TYPES_TO_CONTROL:
            current_status = current_config.get(event_type, "")
            original_status[event_type] = current_status
            print(f"[{vdom_name}] {event_type} current status: {current_status}")
            if current_status == "enable":
                disable_config[event_type] = "disable"
                has_enable = True

        if not has_enable:
            print(f"[{vdom_name}] no events need to be disabled")
            return True, original_status

        # print(f"[{vdom_name}] PUT disable config: {json.dumps(disable_config, indent=2, ensure_ascii=False)}")
        put_response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=disable_config)
        if put_response.status_code != 200:
            print(f"[{vdom_name}] disable PUT failed, HTTP {put_response.status_code}, body: {put_response.text[:300]}")
            return False, original_status

        time.sleep(3)

        verify_response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if verify_response.status_code != 200:
            print(f"[{vdom_name}] verify GET failed, HTTP {verify_response.status_code}")
            return False, original_status

        verify_config = verify_response.json().get("results", {})
        # print(f"[{vdom_name}] GET verify config: {json.dumps(verify_config, indent=2, ensure_ascii=False)}")

        verify_ok = True
        for event_type in EVENT_TYPES_TO_CONTROL:
            if original_status.get(event_type) == "enable":
                actual = verify_config.get(event_type, "")
                if actual != "disable":
                    print(f"[{vdom_name}] verify FAILED: {event_type} expected 'disable' but got '{actual}'")
                    verify_ok = False
                else:
                    print(f"[{vdom_name}] {event_type} verify disabled OK")

        if not verify_ok:
            print(f"[{vdom_name}] disable verification failed")
            return False, original_status

        print(f"[{vdom_name}] all events disabled and verified successfully")
        return True, original_status

    try:
        root_ok, SYSTEM_EVENT_ROOT_STATUS = _disable_vdom_events("root")
        vdom_root_ok = root_ok
        vdom1_ok, SYSTEM_EVENT_VDOM1_STATUS = _disable_vdom_events(vdom1)
        vdom2_ok, SYSTEM_EVENT_VDOM2_STATUS = _disable_vdom_events(vdom2)

        return vdom_root_ok and vdom1_ok and vdom2_ok

    except Exception as e:
        print(f"root/{vdom1}/{vdom2} system-event setting failed: {e}")
        return False

def restore_system_events_setting(ip, session, csrf_token, vdom1, vdom2):
    global SYSTEM_EVENT_ROOT_STATUS, SYSTEM_EVENT_VDOM1_STATUS, SYSTEM_EVENT_VDOM2_STATUS
    url = f"https://{ip}/api/v2/cmdb/log/eventfilter"
    vdom_root_ok = False
    vdom1_ok = False
    vdom2_ok = False

    def _restore_vdom_events(vdom_name, original_status):
        if not original_status:
            print(f"[{vdom_name}] no original status recorded, skip restore")
            return True
        events_to_restore = [et for et, st in original_status.items() if st == "enable"]
        if not events_to_restore:
            print(f"[{vdom_name}] no events were originally enabled, skip restore")
            return True

        params = {"datasource": "true", "with_meta": "true", "vdom": vdom_name}
        get_response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if get_response.status_code != 200:
            print(f"[{vdom_name}] get log eventfilter config failed, HTTP {get_response.status_code}")
            return False

        get_data = get_response.json()
        current_config = get_data.get("results", {})

        if not isinstance(current_config, dict):
            print(f"[{vdom_name}] unexpected results type: {type(current_config)}")
            return False

        # print(f"[{vdom_name}] GET current config: {json.dumps(current_config, indent=2, ensure_ascii=False)}")

        restore_config = copy.deepcopy(current_config)
        for event_type in events_to_restore:
            restore_config[event_type] = "enable"
            print(f"[{vdom_name}] will restore {event_type} to: enable")

        # print(f"[{vdom_name}] PUT restore config: {json.dumps(restore_config, indent=2, ensure_ascii=False)}")

        put_response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=restore_config)
        if put_response.status_code != 200:
            print(f"[{vdom_name}] restore PUT failed, HTTP {put_response.status_code}, body: {put_response.text[:300]}")
            return False

        time.sleep(3)

        verify_response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if verify_response.status_code != 200:
            print(f"[{vdom_name}] verify GET failed, HTTP {verify_response.status_code}")
            return False

        verify_config = verify_response.json().get("results", {})
        # print(f"[{vdom_name}] GET verify config: {json.dumps(verify_config, indent=2, ensure_ascii=False)}")

        verify_ok = True
        for event_type in events_to_restore:
            actual = verify_config.get(event_type, "")
            if actual != "enable":
                print(f"[{vdom_name}] verify FAILED: {event_type} expected 'enable' but got '{actual}'")
                verify_ok = False
            else:
                print(f"[{vdom_name}] {event_type} verify restored to 'enable' OK")

        if not verify_ok:
            print(f"[{vdom_name}] restore verification failed")
            return False

        print(f"[{vdom_name}] all events restored and verified successfully")
        return True

    try:
        vdom_root_ok = _restore_vdom_events("root", SYSTEM_EVENT_ROOT_STATUS)
        vdom1_ok = _restore_vdom_events(vdom1, SYSTEM_EVENT_VDOM1_STATUS)
        vdom2_ok = _restore_vdom_events(vdom2, SYSTEM_EVENT_VDOM2_STATUS)

        return vdom_root_ok and vdom1_ok and vdom2_ok

    except Exception as e:
        print(f"root/{vdom1}/{vdom2} system-event restore failed: {e}")
        return False

def disable_log_syslogd_setting(ip, session, csrf_token):
    global SYSLOGD_ORIGINAL_STATUS
    url = f"https://{ip}/api/v2/cmdb/log.syslogd/setting"
    params = {
        "datasource": "true",
        "with_meta": "true"
    }
    syslogd_ok = False

    try:
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            status = results.get("status", "")
            print(f"syslogd global status: {status}")
            SYSLOGD_ORIGINAL_STATUS = status
            if status == "enable":
                disable_config = copy.deepcopy(results)
                disable_config.update({"status": "disable"})
                response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=disable_config)
                if response.status_code == 200:
                    syslogd_ok = True
                    print("syslogd global disable success")
            elif status == "disable":
                print("syslogd global no need to disable")
                syslogd_ok = True

        return syslogd_ok

    except Exception as e:
        print(f"syslogd global setting failed: {e}")
        return False

def restore_log_syslogd_setting(ip, session, csrf_token):
    global SYSLOGD_ORIGINAL_STATUS
    url = f"https://{ip}/api/v2/cmdb/log.syslogd/setting"
    params = {
        "datasource": "true",
        "with_meta": "true"
    }
    syslogd_ok = False

    try:
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        if response.status_code == 200:
            results = response.json().get("results", {})
            current_status = results.get("status", "")
            target_status = SYSLOGD_ORIGINAL_STATUS
            print(f"syslogd current status: {current_status}, original status: {target_status}")
            if current_status != target_status:
                restore_config = copy.deepcopy(results)
                restore_config.update({"status": target_status})
                response = session.put(url, headers={"X-CSRFTOKEN": csrf_token}, params=params, json=restore_config)
                if response.status_code == 200:
                    syslogd_ok = True
                    print(f"syslogd global restore to {target_status} success")
            else:
                print("syslogd global status consistent, no need to restore")
                syslogd_ok = True

        return syslogd_ok

    except Exception as e:
        print(f"syslogd global restore failed: {e}")
        return False

def create_vdom_link(ip, session, csrf_token, link_name, vdom1, vdom2):

    vdom_link_list = get_vdom_link_list(FORTIGATE_IP, session, csrf_token)
    if link_name in vdom_link_list:
        print(f"vdom-link '{link_name}' is already exists, skip creation.")
        return True

    url = f"https://{ip}/api/v2/cmdb/system/vdom-link"

    payload = {
        "name": link_name,
        "type": "ppp",
        "vcluster": "vcluster1"
    }
    
    response = session.post(
        url,
        headers={"X-CSRFTOKEN": csrf_token},
        json=payload
    )
    
    if response.status_code == 200:
        print(f"create vdom-link '{link_name}' successfully")
        
        url = f"https://{ip}/api/v2/cmdb/system/interface/{link_name}0"

        payload = {
            "name": f"{link_name}0",
            "vdom": {"q_origin_key": vdom1},
            "ip": f"{VDOM_LINK_0_IP}/255.255.255.0",
            "type": "vdom-link",
            "allowaccess": "https http ping ssh"
        }

        response = session.put(
            url,
            headers={"X-CSRFTOKEN": csrf_token},
            json=payload
        )
        if response.status_code == 200:
            print(f"create set interface {link_name}0 IP: {VDOM_LINK_0_IP}/255.255.255.0 successfully")

            url = f"https://{ip}/api/v2/cmdb/system/interface/{link_name}1"
            payload = {
                "name": f"{link_name}1",
                "vdom": {"q_origin_key": vdom2},
                "ip": f"{VDOM_LINK_1_IP}/255.255.255.0",
                "type": "vdom-link",
                "allowaccess": "https http ping ssh"
            }
            response = session.put(
                url,
                headers={"X-CSRFTOKEN": csrf_token},
                json=payload
            )
            if response.status_code == 200:
                print(f"create set interface {link_name}1 IP: {VDOM_LINK_1_IP}/255.255.255.0 successfully")
            elif response.status_code == 400:
                print(f"create interface {link_name}1 failed")
                print(response.text)
                return False

        return True
    else:
        print(f"create vdom-link failed: HTTP {response.status_code}")
        print(response.text)
        return False

def get_vdom_link_list(ip, session, csrf_token):
    url = f"https://{ip}/api/v2/cmdb/system/vdom-link"
    
    try:
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token})
        if response.status_code == 200:
            links = response.json().get("results", [])
            return [link["name"] for link in links]
        else:
            print(f"get vdom-link list failed: HTTP {response.status_code}")
            return []
    except Exception as e:
        print(f"get vdom-link list error: {e}")
        return []

def restore_vdom_link_config(ip, session, csrf_token, vdom1, vdom2, link_name):
    """
    自动恢复/删除 vdom-link 配置，无需用户交互。
    对应原 -d 模式的完整恢复流程。
    """
    print(f"\n[Auto Restore] starting restore for vdoms: {vdom1}, {vdom2}, link: {link_name}")

    if not disable_system_events_setting(ip, session, csrf_token, vdom1, vdom2):
        print(f"root/{vdom1}/{vdom2} system events not disabled")
        logout_from_fortigate(ip, session, csrf_token)
        return False

    if not disable_log_syslogd_setting(ip, session, csrf_token):
        print("global syslogd setting not disabled")
        logout_from_fortigate(ip, session, csrf_token)
        return False

    print(f"delete firewall policy in VDOM '{vdom1}' and '{vdom2}'...")
    delete_firewall_policy_by_name(ip, session, csrf_token, vdom1)
    delete_firewall_policy_by_name(ip, session, csrf_token, vdom2)

    print(f"delete static route in VDOM '{vdom1}' and '{vdom2}'...")
    delete_static_route_by_intf(ip, session, csrf_token, vdom1, target_gateway=VDOM_LINK_1_IP)
    delete_static_route_by_intf(ip, session, csrf_token, vdom2, target_gateway=VDOM_LINK_0_IP)

    vdom_link_list = get_vdom_link_list(ip, session, csrf_token)
    if link_name in vdom_link_list:
        print(f"delete vdom-link {link_name}...")
        delete_vdom_link(ip, session, csrf_token, link_name)
        vdom_link_list = get_vdom_link_list(ip, session, csrf_token)
        print("get new vdom_link list:", vdom_link_list)
    else:
        print(f"vdom-link {link_name} does not exist, Skip deletion.")

    if restore_log_syslogd_setting(ip, session, csrf_token):
        print("global syslogd setting restored")

    if restore_system_events_setting(ip, session, csrf_token, vdom1, vdom2):
        print(f"root/{vdom1}/{vdom2} system events setting restored")
    else:
        print(f"root/{vdom1}/{vdom2} system events setting not restored")

    print("[Auto Restore] restore completed.")
    return True

def delete_vdom_link(ip, session, csrf_token, link_name):
    url = f"https://{ip}/api/v2/cmdb/system/vdom-link/{link_name}"
    
    try:
        response = session.delete(
            url,
            headers={"X-CSRFTOKEN": csrf_token}
        )
        
        if response.status_code == 200:
            print(f"delete vdom-link '{link_name}' successfully")
            return True
        else:
            print(f"delete vdom-link failed: HTTP {response.status_code}")
            print(response.text)
            return False
            
    except Exception as e:
        print(f"delete vdom-link error: {e}")
        return False

def create_firewall_policy(ip, session, csrf_token, vdom_name, policy_config):
    url = f"https://{ip}/api/v2/cmdb/firewall/policy"
    
    try:
        params = {"vdom": vdom_name}
        response = session.post(
            url,
            headers={"X-CSRFTOKEN": csrf_token},
            params=params,
            data=json.dumps(policy_config)
        )
        
        if response.status_code == 200:
            print(f"create firewall policy '{policy_config['name']}' in VDOM '{vdom_name}' successfully")
            return True
        else:
            print(f"create firewall policy failed: HTTP {response.status_code}")
            print(response.text)
            return False
            
    except Exception as e:
        print(f"create firewall policy error: {e}")
        return False

def delete_firewall_policy(ip, session, csrf_token, vdom_name, policy_id):
    url = f"https://{ip}/api/v2/cmdb/firewall/policy/{policy_id}"

    try:
        params = {"vdom": vdom_name}
        response = session.delete(
            url,
            headers={"X-CSRFTOKEN": csrf_token},
            params=params
        )

        if response.status_code == 200:
            print(f"delete firewall policy in VDOM '{vdom_name}' with ID: {policy_id} successfully")
            return True
        else:
            print(f"delete firewall policy failed: HTTP {response.status_code}")
            print(response.text)
            return False

    except Exception as e:
        print(f"delete firewall policy error: {e}")
        return False

def delete_firewall_policy_by_name(ip, session, csrf_token, vdom_name):

    get_url = f"https://{ip}/api/v2/cmdb/firewall/policy"
    get_params = {"vdom": vdom_name}
    
    try:
        get_response = session.get(
            get_url,
            headers={"X-CSRFTOKEN": csrf_token},
            params=get_params,
            verify=False
        )
        
        if get_response.status_code != 200:
            print(f"get firewall policy list failed: HTTP {get_response.status_code}")
            print(get_response.text)
            return False
            
        data = get_response.json()
        all_policies = data.get("results", [])
        policies_to_delete = []

        policy_name_list = [f"{POLICY_PREFIX}{vdom_name}-in", f"{POLICY_PREFIX}{vdom_name}-out"]
        for policy in all_policies:
            for policy_name in policy_name_list:
                if policy.get("name") == policy_name:
                    policy_id = policy.get("policyid")
                    if policy_id is not None:
                        policies_to_delete.append(policy_id)
                        print(f"Found policy matched: ID={policy_id}, name={policy.get('name')}")
                    else:
                        print("Found policy but missing 'policyid' field.")

        if not policies_to_delete:
            print(f"Not found firewall policies in VDOM '{vdom_name}' with names: {policy_name_list}")
            return False

        deletion_success = True
        for pid in policies_to_delete:
            success = delete_firewall_policy(ip, session, csrf_token, vdom_name, pid)
            if not success:
                deletion_success = False

        return deletion_success

    except Exception as e:
        print(f"delete firewall policy by name error: {e}")
        return False

def create_static_route(ip, session, csrf_token, vdom_name, route_config):

    url = f"https://{ip}/api/v2/cmdb/router/static"
    
    try:
        params = {"vdom": vdom_name}

        response = session.get(
            f"{url}?filter=dst=={route_config['dst']}",
            headers={"X-CSRFTOKEN": csrf_token},
            params=params
        )
        
        if response.status_code == 200:
            results = response.json().get("results", [])
            if any(route["dst"] == route_config["dst"] for route in results):
                print(f"static route {route_config['dst']} in '{vdom_name}' is already exists, skip creation.")
                return True

        response = session.post(
            url,
            headers={"X-CSRFTOKEN": csrf_token},
            params=params,
            data=json.dumps(route_config)
        )
        
        if response.status_code == 200:
            print(f"create static route  {route_config['dst']} in '{vdom_name}' successfully")
            return True
        else:
            print(f"create static route failed: HTTP {response.status_code}, {response.text}")
            return False
            
    except Exception as e:
        print(f"create static route error: {e}")
        return False

def delete_static_route(ip, session, csrf_token, vdom_name, route_id):
    url = f"https://{ip}/api/v2/cmdb/router/static/{route_id}"
    
    try:
        params = {"vdom": vdom_name}
        
        response = session.delete(
            url,
            headers={"X-CSRFTOKEN": csrf_token},
            params=params
        )
        
        if response.status_code == 200:
            print(f"delete static route ID: {route_id} in VDOM '{vdom_name}' successfully")
            return True
        else:
            print(f"delete static route failed: HTTP {response.status_code}")
            print(response.text)
            return False
            
    except Exception as e:
        print(f"delete static route error: {e}")
        return False

def delete_static_route_by_intf(ip, session, csrf_token, vdom_name, target_interface_name=None, target_gateway=None):

    get_url = f"https://{ip}/api/v2/cmdb/router/static"
    get_params = {"vdom": vdom_name}
    
    try:
        get_response = session.get(
            get_url,
            headers={"X-CSRFTOKEN": csrf_token},
            params=get_params,
            verify=False
        )
        
        if get_response.status_code != 200:
            print(f"get static route list failed: HTTP {get_response.status_code}")
            print(get_response.text)
            return False
            
        data = get_response.json()
        all_routes = data.get("results", [])
        routes_to_delete = [] 

        for route in all_routes:
            if target_interface_name is not None:
                device_name = route.get("device", {}).get("name", "") if isinstance(route.get("device"), dict) else ""
                if device_name != target_interface_name:
                    continue

            if target_gateway is not None and route.get("gateway") != target_gateway:
                continue

            route_id = route.get("seq-num")
            if route_id is not None:
                routes_to_delete.append(route_id)
                print(f"found route matched: ID={route_id}, gateway={route.get('gateway')}, device={route.get('device')}")
            else:
                print("found route without seq-num field.")

        if not routes_to_delete:
            print(f"not found static route in VDOM '{vdom_name}' that matches the given criteria.")
            return False

        deletion_success = True
        for rid in routes_to_delete:
            success = delete_static_route(ip, session, csrf_token, vdom_name, rid)
            if not success:
                deletion_success = False

        return deletion_success

    except Exception as e:
        print(f"delete static route by interface error: {e}")
        return False

def get_vdom_interfaces(ip, session, csrf_token, vdom_name):    
    url = f"https://{ip}/api/v2/monitor/system/available-interfaces"
    
    try:
        params = {"scope": "global"}
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        
        if response.status_code == 200:
            intf_list = []
            results = response.json().get("results", [])
            for intf_detail in results:
                vdom = intf_detail.get("vdom")
                if vdom_name == vdom:
                    intf_name = intf_detail.get("name", "")
                    if intf_name:
                        intf_list.append(intf_name)
            return intf_list
        else:
            print(f"get interface list failed: HTTP {response.status_code}")
            return []
    except Exception as e:
        print(f"get interface list error: {e}")
        return []

def get_vdom_interface_details(ip, session, csrf_token, vdom_name, interface_name):
    url = f"https://{ip}/api/v2/cmdb/system/interface/{interface_name}"
    
    try:
        params = {"vdom": vdom_name}
        response = session.get(url, headers={"X-CSRFTOKEN": csrf_token}, params=params)
        
        if response.status_code == 200:
            results = response.json().get("results", [])
            results_list = results[0] if isinstance(results, list) and results else results
            return {
                "name": results_list.get("name"),
                "vdom": results_list.get("vdom"),
                "ip": results_list.get("ip"),
                "secondaryip": results_list.get("secondaryip", [])
            }
        else:
            print(f"get interface details failed: HTTP {response.status_code}")
            return {}
    except Exception as e:
        print(f"get interface details error: {e}")
        return {}

def get_next_policy_id(ip, session, csrf_token, vdom, increment=100):
    url = f"https://{ip}/api/v2/cmdb/firewall/policy"
    params = {"vdom": vdom}
    
    try:
        response = session.get(
            url,
            params=params,
            headers={"X-CSRFTOKEN": csrf_token},
            verify=False
        )

        if response.status_code != 200:
            print(f"get policy list failed: HTTP {response.status_code}")
            return None

        data = response.json()
        max_id = 0
        for policy in data["results"]:
            policy_id = policy.get("policyid", 0)
            if policy_id > max_id:
                max_id = policy_id

        if max_id == 0:
            return increment
        next_id = max_id + increment
        
        print(f"VDOM '{vdom}': max policy ID: {max_id}, the next unuse ID: {next_id}")
        return next_id
        
    except Exception as e:
        print(f"get next policy ID error: {e}")
        return None

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Set Fortigate VDOM interface config')
    parser.add_argument('-t', '--fortigate-ip', required=True, help='Fortigate device ipv4 address (e.g. 192.168.2.128)')
    parser.add_argument('-u', '--username', required=True, help='Fortigate admin username (e.g. admin)')
    parser.add_argument('-p', '--password', required=True, help='Fortigate admin password (e.g. admin)')
    parser.add_argument('-d', '--delete', action='store_true', help='Enter delete vdom-link mode')
    parser.add_argument('--auto-restore', type=int, default=0, help='Auto restore after N seconds (default: 0, disabled)')

    args = parser.parse_args()

    FORTIGATE_IP = args.fortigate_ip
    USERNAME = args.username
    PASSWORD = args.password
    link_success = False  

    session, csrf_token = login_to_fortigate(
        ip=FORTIGATE_IP,
        username=USERNAME,
        password=PASSWORD,
        verify_ssl=False
    )
    
    if session and csrf_token:
        print("login successful.")
        
        vdom_list = get_vdom_list(FORTIGATE_IP, session, csrf_token)
        print("get vdom list:", vdom_list)
        vdom_link_list = get_vdom_link_list(FORTIGATE_IP, session, csrf_token)
        print("get vdom_link list:", vdom_link_list)

        if args.delete:
            print("Input 2 vdoms name needed to restore：")
            vdom1 = input("1st vdom name:")
            vdom2 = input("2nd vdom name:")
            
            link_name = input("Input vdom-link name needed to delete:")
            restore_vdom_link_config(FORTIGATE_IP, session, csrf_token, vdom1, vdom2, link_name)
            logout_from_fortigate(FORTIGATE_IP, session, csrf_token)
            exit(0)

        print("Input 2 vdoms name needed to create vdom-link:")
        vdom1 = input("1st vdom name:")
        vdom2 = input("2nd vdom name:")
        if vdom1 in vdom_list and vdom2 in vdom_list:
            intf1_list = get_vdom_interfaces(FORTIGATE_IP, session, csrf_token, vdom1)
            intf2_list = get_vdom_interfaces(FORTIGATE_IP, session, csrf_token, vdom2)
            print(f"{vdom1} interface list:", intf1_list)
            print(f"{vdom2} interface list:", intf2_list)

            intf1 = input(f"input {vdom1} interface name:")
            intf2 = input(f"input {vdom2} interface name:")
            inf1_detail = get_vdom_interface_details(FORTIGATE_IP, session, csrf_token, vdom1, intf1)
            inf2_detail = get_vdom_interface_details(FORTIGATE_IP, session, csrf_token, vdom2, intf2)


            print(f"{vdom1} interface {intf1} details:", inf1_detail)
            print(f"{intf1} ip address: ", inf1_detail["ip"].split()[0])
            print(f"{vdom2} interface {intf2} details:", inf2_detail)
            print(f"{intf2} ip address: ", inf2_detail["ip"].split()[0])

            #system events
            system_events_result = disable_system_events_setting(FORTIGATE_IP, session, csrf_token, vdom1, vdom2)
            print(f"disable system events result: {system_events_result}")
            if not system_events_result:
                print(f"root/{vdom1}/{vdom2} system events not disabled")
                logout_from_fortigate(FORTIGATE_IP, session, csrf_token)
                exit(0)

            #syslogd
            syslogd_result = disable_log_syslogd_setting(FORTIGATE_IP, session, csrf_token)
            print(f"disable global syslogd result: {syslogd_result}")
            if not syslogd_result:
                print("global syslogd setting not disabled")
                logout_from_fortigate(FORTIGATE_IP, session, csrf_token)
                exit(0)

            # config_disable = disable_config_log_disk_setting(FORTIGATE_IP, session, csrf_token, vdom1, vdom2) & \
            #     disable_config_log_memory_setting(FORTIGATE_IP, session, csrf_token, vdom1, vdom2)
            # if config_disable:
            #     print(f"root/{vdom1}/{vdom2} log setting disabled")
            # else:
            #     print(f"root/{vdom1}/{vdom2} log setting not disabled")
            #     exit(0)

            print("create vdom-link and config interface...")
            print("\n")
            link_name = f"{VDOM_LINK_PREFIX}{vdom1}-{vdom2}"
            link_name = link_name[:10]
            if link_name in vdom_link_list:
                print(f"{vdom1} and {vdom2} vdom-link '{link_name}' already exists, skip creation.")
                link_success = True
            else:
                link_success = create_vdom_link(
                    ip=FORTIGATE_IP,
                    session=session,
                    csrf_token=csrf_token,
                    link_name=link_name,
                    vdom1=vdom1,
                    vdom2=vdom2
                )
            if link_success:               
                print("\n")
                print("create static routes...")
                inf1_addr_ip = input(f"input {vdom1} IP address to be redirected (single IP):")
                inf2_addr_ip = input(f"input {vdom2} IP address to be redirected (single IP):")
                inf1_addr = f"{inf1_addr_ip} 255.255.255.255"
                inf2_addr = f"{inf2_addr_ip} 255.255.255.255"
                vd_link_inf0 = f"{link_name}0"
                vd_link_inf1 = f"{link_name}1"
                vdom1_static_route_success = create_static_route(
                    ip=FORTIGATE_IP,
                    session=session,
                    csrf_token=csrf_token,
                    vdom_name=vdom1,
                    route_config={
                        "dst": inf2_addr,
                        "gateway": VDOM_LINK_1_IP,
                        "device": {"q_origin_key": vd_link_inf0},
                        "comment": f"{STATIC_ROUTE_PREFIX}{vdom1}-route"
                    }
                ) 

                vdom2_static_route_success = create_static_route(
                    ip=FORTIGATE_IP,
                    session=session,
                    csrf_token=csrf_token,
                    vdom_name=vdom2,
                    route_config={
                        "dst": inf1_addr,
                        "gateway": VDOM_LINK_0_IP,
                        "device": {"q_origin_key": vd_link_inf1},
                        "comment": f"{STATIC_ROUTE_PREFIX}{vdom2}-route"
                    }
                ) 

                if vdom1_static_route_success and vdom2_static_route_success:
                    print("create static routes successfully!")
                    print("\n")

                    vd_link_inf0 = f"{link_name}0"
                    vd_link_inf1 = f"{link_name}1"
                    vdom1_in_policyid = get_next_policy_id(FORTIGATE_IP, session, csrf_token, vdom1)
                    print(f"vdom1_in_policyid: {vdom1_in_policyid}")
                    vdom1_policy_in_config = copy.deepcopy(vdom_policy_template)
                    vdom1_policy_in_config.update({
                        "policyid": vdom1_in_policyid,
                        "srcintf": [{"name": intf1}],
                        "dstintf": [{"name": vd_link_inf0}],
                        "name": f"{POLICY_PREFIX}{vdom1}-in",
                    })

                    vdom1_fw_in_success = create_firewall_policy(
                        ip=FORTIGATE_IP,
                        session=session,
                        csrf_token=csrf_token,
                        vdom_name=vdom1,
                        policy_config=vdom1_policy_in_config
                    )
                    if vdom1_fw_in_success:
                        print("VDOM1-in firewall policy created successfully!")

                    vdom1_out_policyid = get_next_policy_id(FORTIGATE_IP, session, csrf_token, vdom1)
                    print(f"vdom1_out_policyid: {vdom1_out_policyid}")
                    vdom1_policy_out_config = copy.deepcopy(vdom_policy_template)
                    vdom1_policy_out_config.update({
                        "policyid": vdom1_out_policyid,
                        "srcintf": [{"name": vd_link_inf0}],
                        "dstintf": [{"name": intf1}],
                        "name": f"{POLICY_PREFIX}{vdom1}-out",
                    })

                    vdom1_fw_out_success = create_firewall_policy(
                        ip=FORTIGATE_IP,
                        session=session,
                        csrf_token=csrf_token,
                        vdom_name=vdom1,
                        policy_config=vdom1_policy_out_config
                    )
                    if vdom1_fw_out_success:
                        print("VDOM1-out firewall policy created successfully!")

                    vdom2_in_policyid = get_next_policy_id(FORTIGATE_IP, session, csrf_token, vdom2)
                    print(f"vdom2_in_policyid: {vdom2_in_policyid}")
                    vdom2_policy_in_config = copy.deepcopy(vdom_policy_template)
                    vdom2_policy_in_config.update({
                        "policyid": vdom2_in_policyid,
                        "srcintf": [{"name": intf2}],
                        "dstintf": [{"name": vd_link_inf1}],
                        "name": f"{POLICY_PREFIX}{vdom2}-out",
                    })

                    vdom2_fw_in_success = create_firewall_policy(
                        ip=FORTIGATE_IP,
                        session=session,
                        csrf_token=csrf_token,
                        vdom_name=vdom2,
                        policy_config=vdom2_policy_in_config
                    )
                    if vdom2_fw_in_success:
                        print("VDOM2-in firewall policy created successfully!")

                    vdom2_out_policyid = get_next_policy_id(FORTIGATE_IP, session, csrf_token, vdom2)
                    print(f"vdom2_out_policyid: {vdom2_out_policyid}")
                    vdom2_policy_out_config = copy.deepcopy(vdom_policy_template)
                    vdom2_policy_out_config.update({
                        "policyid": vdom2_out_policyid,
                        "srcintf": [{"name": vd_link_inf1}],
                        "dstintf": [{"name": intf2}],
                        "name": f"{POLICY_PREFIX}{vdom2}-in",
                    })

                    vdom2_fw_out_success = create_firewall_policy(
                        ip=FORTIGATE_IP,
                        session=session,
                        csrf_token=csrf_token,
                        vdom_name=vdom2,
                        policy_config=vdom2_policy_out_config
                    )
                    if vdom2_fw_out_success:
                        print("VDOM2-out firewall policy created successfully!")

                    if vdom1_fw_in_success and vdom1_fw_out_success and vdom2_fw_in_success and vdom2_fw_out_success:
                        print("firewall policies created successfully!")
                        print("\n")
                    
                    # if enable_config_log_memory_setting(FORTIGATE_IP, session, csrf_token, vdom1, vdom2):
                    #     print(f"root/{vdom1}/{vdom2}log-memory setting restored")
                    # else:
                    #     print(f"root/{vdom1}/{vdom2}log-memory setting not restored")

                    # if enable_config_log_disk_setting(FORTIGATE_IP, session, csrf_token, vdom1, vdom2):
                    #     print(f"root/{vdom1}/{vdom2}log-disk setting restored")
                    # else:
                    #     print(f"root/{vdom1}/{vdom2}log-disk setting not restored")
                    
                    if restore_log_syslogd_setting(FORTIGATE_IP, session, csrf_token):
                        print("global syslogd setting restored")

                    if restore_system_events_setting(FORTIGATE_IP, session, csrf_token, vdom1, vdom2):
                        print(f"root/{vdom1}/{vdom2} system events setting restored")
                    else:
                        print(f"root/{vdom1}/{vdom2} system events setting not restored")

                    # auto-restore
                    if args.auto_restore > 0:
                        print(f"\n[Timer] will auto restore after {args.auto_restore} seconds...")
                        print(f"[Timer] recorded vdom1={vdom1}, vdom2={vdom2}, link_name={link_name}")
                        time.sleep(args.auto_restore)
                        print("\n[Timer] auto restore triggered.")
                        # 重新登录获取新会话（旧会话可能已超时）
                        if args.auto_restore >= 300:
                            print("[Timer] auto restore within 5 minutes, reuse current session.")
                            session, csrf_token = login_to_fortigate(
                                ip=FORTIGATE_IP,
                                username=USERNAME,
                                password=PASSWORD,
                                verify_ssl=False
                            )

                        if session and csrf_token:
                            restore_vdom_link_config(FORTIGATE_IP, session, csrf_token, vdom1, vdom2, link_name)
                            logout_from_fortigate(FORTIGATE_IP, session, csrf_token)
                        else:
                            print("[Timer] re-login failed, cannot perform auto restore.")
                    
                    else:
                        # logout
                        logout_from_fortigate(FORTIGATE_IP, session, csrf_token)