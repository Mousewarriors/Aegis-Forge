import json
import httpx
import sys
import os
import asyncio

async def parse_and_report(run_id: str):
    eval_dir = os.path.abspath(os.path.join(os.getcwd(), "..", "promptfoo-eval"))
    report_file = os.path.join(eval_dir, f"report-{run_id}.json")
    callback_url = "http://localhost:8000/campaigns/promptfoo_callback"

    if not os.path.exists(report_file):
        print(f"Report file not found: {report_file}")
        return

    try:
        with open(report_file, "r") as f:
            data = json.load(f)
            
        results = data.get("results", {}).get("results", [])
        print(f"Processing {len(results)} promptfoo results for run {run_id}...")

        async with httpx.AsyncClient(timeout=10.0) as client:
            for res in results:
                passed = res.get("success", False)
                if not passed:
                    # Report failure to callback
                    payload = {
                        "run_id": run_id,
                        "plugin_id": res.get("pluginId", "unknown"),
                        "prompt": res.get("prompt", {}).get("raw", ""),
                        "response": res.get("response", {}).get("output", ""),
                        "reason": res.get("error", "Failed")
                    }
                    try:
                        resp = await client.post(callback_url, json=payload)
                        resp.raise_for_status()
                    except Exception as e:
                        print(f"Failed to send callback for result: {e}")

        print(f"Finished processing results for run {run_id}.")

    except Exception as e:
        print(f"Error parsing report {run_id}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_promptfoo_results.py <run_id>")
        sys.exit(1)
        
    run_id = sys.argv[1]
    asyncio.run(parse_and_report(run_id))
