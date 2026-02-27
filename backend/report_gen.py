import json
from typing import List, Dict, Any
from models import ScenarioRun, FullReport, ReportSummary, Outcome

class ReportGenerator:
    def generate_full_report(self, runs: List[Dict[str, Any]]) -> FullReport:
        pass_count = sum(1 for r in runs if r["outcome"] == Outcome.PASS)
        warn_count = sum(1 for r in runs if r["outcome"] == Outcome.WARNING)
        fail_count = sum(1 for r in runs if r["outcome"] == Outcome.FAIL)
        
        top_risks = []
        if fail_count > 0:
            # Extract names of failed exploits
            failed_names = list(set([r["payload_id"] for r in runs if r["outcome"] == Outcome.FAIL]))
            top_risks = [f"Successful execution of {name}" for name in failed_names]

        recommendations = [
            "Enforce strict tool call allowlists in production.",
            "Use non-root users and PID isolation in agent containers.",
            "Implement a separate policy layer to validate all tool parameters."
        ]
        if fail_count > 0:
            recommendations.append("Immediate: Review sandbox hardening specifically for command execution sinks.")

        summary = ReportSummary(
            total_runs=len(runs),
            pass_count=pass_count,
            warn_count=warn_count,
            fail_count=fail_count,
            top_risks=top_risks,
            recommendations=recommendations
        )
        
        # Convert run dicts to models
        run_models = [ScenarioRun(**r) for r in runs]
        
        return FullReport(summary=summary, runs=run_models)

    def to_human_readable(self, report: FullReport) -> str:
        s = report.summary
        output = [
            "# AI Agent Security Assessment Report",
            f"**Total Runs**: {s.total_runs} | **Pass**: {s.pass_count} | **Warning**: {s.warn_count} | **Fail**: {s.fail_count}",
            "\n## Top Risks Detected",
        ]
        
        if not s.top_risks:
            output.append("- No critical risks detected in this campaign.")
        else:
            for risk in s.top_risks:
                output.append(f"- [CRITICAL] {risk}")
        
        output.append("\n## Detailed Findings")
        for run in report.runs:
            status_icon = "✅" if run.outcome == Outcome.PASS else "⚠️" if run.outcome == Outcome.WARNING else "❌"
            output.append(f"### {status_icon} Scenario: {run.payload_id} ({run.mode})")
            output.append(f"- **Category**: {run.category}")
            output.append(f"- **Outcome**: {run.outcome}")
            if run.evidence.tool_calls_attempted:
                output.append(f"- **Tool Attempted**: `{run.evidence.tool_calls_attempted[0].get('tool')}`")
            if run.evidence.stdout:
                output.append(f"- **Stdout Snippet**: `{run.evidence.stdout[:100]}...`")

        output.append("\n## Recommendations")
        for rec in s.recommendations:
            output.append(f"- {rec}")
            
        return "\n".join(output)

report_gen = ReportGenerator()
