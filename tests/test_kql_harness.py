"""Unit tests for the datatable-based KQL test harness."""

from __future__ import annotations

from pathlib import Path

from pipeline.kql_harness import evaluate_kql, render_datatable_kql, run_harness

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_evaluate_kql_where_and_project() -> None:
    query = """
    DeviceProcessEvents
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any ("-enc", "-encodedcommand")
    | where not(InitiatingProcessFileName in~ ("ccmexec.exe", "intunemanagementextension.exe"))
    | project DeviceName, FileName
    """
    rows = [
        {
            "DeviceName": "ws-01",
            "FileName": "POWERSHELL.EXE",
            "InitiatingProcessFileName": "cmd.exe",
            "ProcessCommandLine": "powershell.exe -enc SQBFAFgA",
        },
        {
            "DeviceName": "ws-02",
            "FileName": "powershell.exe",
            "InitiatingProcessFileName": "IntuneManagementExtension.exe",
            "ProcessCommandLine": "powershell.exe -enc SQBFAFgA",
        },
    ]
    hits = evaluate_kql(query, {"DeviceProcessEvents": rows})
    assert hits == [{"DeviceName": "ws-01", "FileName": "POWERSHELL.EXE"}]


def test_evaluate_kql_summarize_countif_and_make_set() -> None:
    query = """
    CommonSecurityLog
    | where DeviceVendor =~ "Fortinet"
    | summarize Fails = countif(DeviceAction has "fail"), Wins = countif(DeviceAction has "ok"),
        Users = make_set(DestinationUserName, 5) by SourceIP
    | where Fails >= 2 and Wins >= 1
    | extend User = tostring(Users[0])
    | project SourceIP, Fails, Wins, User
    """
    rows = [
        {
            "DeviceVendor": "Fortinet",
            "DeviceAction": "ssl-login-fail",
            "SourceIP": "203.0.113.1",
            "DestinationUserName": "alice",
        },
        {
            "DeviceVendor": "Fortinet",
            "DeviceAction": "ssl-login-fail",
            "SourceIP": "203.0.113.1",
            "DestinationUserName": "alice",
        },
        {
            "DeviceVendor": "Fortinet",
            "DeviceAction": "ssl-login-ok",
            "SourceIP": "203.0.113.1",
            "DestinationUserName": "alice",
        },
        {
            "DeviceVendor": "Fortinet",
            "DeviceAction": "ssl-login-fail",
            "SourceIP": "203.0.113.2",
            "DestinationUserName": "bob",
        },
    ]
    hits = evaluate_kql(query, {"CommonSecurityLog": rows})
    assert hits == [{"SourceIP": "203.0.113.1", "Fails": 2, "Wins": 1, "User": "alice"}]


def test_render_datatable_kql_wraps_query() -> None:
    kql = render_datatable_kql(
        "DeviceProcessEvents",
        [{"DeviceName": "ws-01", "ReportId": 42}],
        'DeviceProcessEvents | where DeviceName == "ws-01"',
    )
    assert kql.startswith("let DeviceProcessEvents = datatable(DeviceName:string, ReportId:long)")
    assert '"ws-01", 42' in kql


def test_all_repository_rules_pass_kql_harness() -> None:
    assert run_harness(REPO_ROOT) == []
