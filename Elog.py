import subprocess
import json
import time
import re

class Elog:
    def run_powershell(self, cmd: str):
        process = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, encoding="utf-8"
        )
        return self._parse_output(process.stdout.strip(), process.stderr.strip(), process.returncode)

    def _parse_output(self, stdout: str, stderr: str, returncode: int):
        """
        PowerShell'dan kelgan natijani JSON formatga o'tkazadi.
        """
        if returncode == 0:
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return {"error": "JSON formatga o'tkazib bo'lmadi", "raw_output": stdout}
        return {"error": stderr}

    def _format_message(self, message):
        """
        Log xabarlaridagi keraksiz belgilarni tozalaydi.
        """
        message = re.sub(r"\\r|\\n", "\n", message).strip()
        return re.sub(r"\n+", "\n", message)

    def _get_logs(self, cmd: str):
        result = self.run_powershell(cmd)
        if isinstance(result, list):
            for log in result:
                if 'Message' in log:
                    log['Message'] = self._format_message(log['Message'])
        elif isinstance(result, dict) and 'Message' in result:
            result['Message'] = self._format_message(result['Message'])
        return result

    def get_event_logs(self, log_name: str, limit: int = 10):
        cmd = f'Get-EventLog -LogName {log_name} -Newest {limit} | ' \
              f'Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json -Depth 2'
        return self._get_logs(cmd)

    def get_win_event_logs(self, log_name: str, limit: int = 10):
        cmd = f'Get-WinEvent -LogName "{log_name}" -MaxEvents {limit} | ' \
              f'Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Json -Depth 2'
        return self._get_logs(cmd)

    def get_application_logs(self, limit: int = 10):
        return self.get_event_logs('Application', limit)

    def get_security_logs(self, limit: int = 10):
        return self.get_event_logs('Security', limit)

    def get_sysmon_logs(self, limit: int = 10):
        return self.get_win_event_logs('Microsoft-Windows-Sysmon/Operational', limit)

    def get_firewall_logs(self, limit: int = 10):
        return self.get_win_event_logs('Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', limit)

    def get_task_scheduler_logs(self, limit: int = 10):
        return self.get_win_event_logs('Microsoft-Windows-TaskScheduler/Operational', limit)

    def get_powershell_logs(self, limit: int = 10):
        return self.get_win_event_logs('Microsoft-Windows-PowerShell/Operational', limit)

    def get_windows_defender_logs(self, limit: int = 10):
        return self.get_win_event_logs('Microsoft-Windows-Windows Defender/Operational', limit)

    def get_wmi_logs(self, limit: int = 10):
        return self.get_win_event_logs('Microsoft-Windows-WMI-Activity/Operational', limit)

    def monitor_sysmon_logs(self, limit: int = 10, delay: int = 2):
        """
        Sysmon loglarini real vaqt rejimida monitoring qiladi.
        To'xtatish uchun Ctrl + C ni bosing.
        """
        print("🟢 Sysmon monitoring boshlandi... (To‘xtatish: Ctrl + C)")
        try:
            while True:
                logs = self.get_sysmon_logs(limit)
                print(json.dumps(logs, indent=4, ensure_ascii=False))
                time.sleep(delay)
        except KeyboardInterrupt:
            print("\n🔴 Monitoring to‘xtatildi.")
