import subprocess
import json
import time
import re
from datetime import datetime

class Elog:
    def run_powershell(self, cmd):
        process = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, encoding="utf-8"
        )
        return self._parse_output(process.stdout.strip(), process.stderr.strip(), process.returncode)

    def _parse_output(self, stdout, stderr, returncode):
        if returncode == 0:
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return {"error": "JSON parse error", "raw_output": stdout}
        return {"error": stderr}

    def _convert_dotnet_date(self, date_str):
        m = re.match(r"/Date\((\d+)", date_str)
        if m:
            return datetime.utcfromtimestamp(int(m.group(1)) / 1000).strftime("%Y-%m-%d %H:%M:%S")
        return date_str

    def _parse_message_to_dict(self, msg):
        parts = [part.strip() for part in re.split(r';\s*', msg) if part.strip()]
        data = {}
        for part in parts:
            if '=' in part:
                k, v = part.split('=', 1)
                data[k.strip()] = v.strip()
            else:
                data.setdefault('Description', part)
        return data

    def _format_logs(self, logs):
        if isinstance(logs, list):
            for log in logs:
                for k in ['TimeCreated', 'TimeGenerated']:
                    if k in log and isinstance(log[k], str):
                        log[k] = self._convert_dotnet_date(log[k])
                if 'Message' in log:
                    log['Message'] = self._parse_message_to_dict(log['Message'])
        elif isinstance(logs, dict):
            for k in ['TimeCreated', 'TimeGenerated']:
                if k in logs and isinstance(logs[k], str):
                    logs[k] = self._convert_dotnet_date(logs[k])
            if 'Message' in logs:
                logs['Message'] = self._parse_message_to_dict(logs['Message'])
        return logs

    def _get_logs(self, cmd):
        return self._format_logs(self.run_powershell(cmd))

    def get_event_logs(self, log_name, limit=10):
        cmd = f'Get-EventLog -LogName {log_name} -Newest {limit} | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json -Depth 2'
        return self._get_logs(cmd)

    def get_win_event_logs(self, log_name, limit=10):
        cmd = f'Get-WinEvent -LogName "{log_name}" -MaxEvents {limit} | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Json -Depth 2'
        return self._get_logs(cmd)

    def get_application_logs(self, limit=10):
        return self.get_event_logs('Application', limit)

    def get_security_logs(self, limit=10):
        return self.get_event_logs('Security', limit)

    def get_sysmon_logs(self, limit=10):
        return self.get_win_event_logs('Microsoft-Windows-Sysmon/Operational', limit)

    def get_firewall_logs(self, limit=10):
        return self.get_win_event_logs('Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', limit)

    def get_task_scheduler_logs(self, limit=10):
        return self.get_win_event_logs('Microsoft-Windows-TaskScheduler/Operational', limit)

    def get_powershell_logs(self, limit=10):
        return self.get_win_event_logs('Microsoft-Windows-PowerShell/Operational', limit)

    def get_windows_defender_logs(self, limit=10):
        return self.get_win_event_logs('Microsoft-Windows-Windows Defender/Operational', limit)

    def get_wmi_logs(self, limit=10):
        return self.get_win_event_logs('Microsoft-Windows-WMI-Activity/Operational', limit)

    def logs_to_json(self, logs_dict_or_list):
        return json.dumps(logs_dict_or_list, indent=4, ensure_ascii=False)
