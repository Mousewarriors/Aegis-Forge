from monitor import CampaignMonitor


def test_monitor_reset_clears_counters_and_history():
    m = CampaignMonitor()
    m.total_runs = 3
    m.pass_count = 1
    m.warn_count = 1
    m.fail_count = 1
    m.campaign_history = [{"type": "scenario"}]
    m.strategy_stats = {"prompt_injection": {"DAN Jailbreak": {"attempts": 1, "successes": 0}}}

    m.reset()

    assert m.total_runs == 0
    assert m.pass_count == 0
    assert m.warn_count == 0
    assert m.fail_count == 0
    assert m.campaign_history == []
    assert m.strategy_stats == {}
