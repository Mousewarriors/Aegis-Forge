import pytest
from ebpf_monitor import syswatch
from models import KernelEvent

def test_parse_old_schema():
    line = "OPEN|bash|/etc/passwd"
    event = syswatch._parse_bpftrace_line(line)
    assert event is not None
    assert event.event_type == "OPEN"
    assert event.process == "bash"
    assert event.target == "/etc/passwd"
    assert event.is_suspicious is True
    assert event.pid is None

def test_parse_new_schema():
    line = "EXEC|python|1234|567|1000|4026531836|/usr/bin/python3"
    event = syswatch._parse_bpftrace_line(line)
    assert event is not None
    assert event.event_type == "EXEC"
    assert event.process == "python"
    assert event.pid == 1234
    assert event.ppid == 567
    assert event.uid == 1000
    assert event.cgroup == 4026531836
    assert event.target == "/usr/bin/python3"
    # Python is INFO unless in /tmp or hidden
    assert event.is_suspicious is False

def test_parse_new_schema_with_pipe_in_target():
    line = "OPEN|touch|1234|567|1000|0|/var/log/file|with|pipes"
    event = syswatch._parse_bpftrace_line(line)
    assert event is not None
    assert event.target == "/var/log/file|with|pipes"
    assert event.is_suspicious is False

def test_suspicion_open_exact():
    line = "OPEN|cat|1|1|0|0|/etc/shadow"
    event = syswatch._parse_bpftrace_line(line)
    assert event.is_suspicious is True

def test_suspicion_open_prefix():
    line = "OPEN|ls|1|1|0|0|/root/.ssh/authorized_keys"
    event = syswatch._parse_bpftrace_line(line)
    assert event.is_suspicious is True

def test_suspicion_open_safe_proc():
    line = "OPEN|top|1|1|0|0|/proc/meminfo"
    event = syswatch._parse_bpftrace_line(line)
    assert event.is_suspicious is False

def test_suspicion_open_sensitive_proc():
    line = "OPEN|cat|1|1|0|0|/proc/self/environ"
    event = syswatch._parse_bpftrace_line(line)
    assert event.is_suspicious is True

def test_suspicion_exec_alert():
    line = "EXEC|sh|1|1|0|0|/usr/bin/curl"
    event = syswatch._parse_bpftrace_line(line)
    assert event.is_suspicious is True

def test_suspicion_exec_warn():
    line = "EXEC|sudo|1|1|0|0|/bin/bash"
    event = syswatch._parse_bpftrace_line(line)
    assert event.is_suspicious is True

def test_suspicion_exec_tmp():
    line = "EXEC|python|1|1|0|0|/tmp/payload.py"
    event = syswatch._parse_bpftrace_line(line)
    assert event.is_suspicious is True

def test_canary_match():
    line = "OPEN|cat|1|1|0|0|/workspace/.aegis_canary/secret.txt"
    event = syswatch._parse_bpftrace_line(line)
    assert event.is_suspicious is True

def test_ignore_banner():
    line = "[SysWatch] Aegis probe loaded."
    event = syswatch._parse_bpftrace_line(line)
    assert event is None

def test_malformed_line():
    line = "OPEN|incomplete"
    event = syswatch._parse_bpftrace_line(line)
    assert event is None
