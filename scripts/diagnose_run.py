#!/usr/bin/env python3
"""
Detailed diagnostic script for Sitina multi-agent run failure.
Analyzes journal to find exact failure point.
"""
import sys
import json
from pathlib import Path

run_id = "tma-run-4ff58936893f0dd12604390c78040f69936c"

# Find latest journal
journal_dir = Path("/Users/moss/SitinaHub/state/code-mode/sessions")
journals = list(journal_dir.glob("*/journal/active.seg"))
if not journals:
    print("No journal found")
    sys.exit(1)

latest = max(journals, key=lambda p: p.stat().st_mtime)
print(f"Analyzing journal: {latest}\n")

# Read and parse events
events = []
with open(latest, 'rb') as f:
    content = f.read()

# Extract JSON events
text = content.decode('utf-8', errors='ignore')
for line in text.split('\n'):
    if run_id not in line:
        continue
    try:
        event = json.loads(line)
        events.append(event)
    except:
        pass

print(f"Found {len(events)} events for run {run_id}\n")
print("=" * 80)

# Analyze event sequence
for i, event in enumerate(events, 1):
    et = event.get('event_type', '')
    p = event.get('payload', {})

    print(f"\n[{i}] {et}")
    print(f"    Time: {event.get('occurred_at', 'N/A')}")

    # Show key fields based on event type
    if 'created' in et:
        print(f"    ✓ Run created")
        print(f"    External mutation: {p.get('external_mutation_allowed')}")
        print(f"    Intent authorized: {p.get('intent_authorized')}")

    elif 'scheduling' in et:
        decision = p.get('decision', {})
        print(f"    Selected agents: {decision.get('selected_agents', [])}")
        print(f"    Task: {p.get('task_id')}")

    elif 'agent' in et.lower():
        print(f"    Agent: {p.get('agent_id', 'N/A')}")
        print(f"    Task: {p.get('task_id', 'N/A')}")

    elif 'protocol' in et:
        print(f"    Protocol: {p.get('protocol_name', 'N/A')}")
        print(f"    Status: {p.get('terminal_disposition', p.get('status', 'N/A'))}")

    elif 'failed' in et or 'error' in et.lower():
        print(f"    ✗ ERROR!")
        print(f"    Error type: {p.get('error_type')}")
        print(f"    Terminal state: {p.get('terminal_state')}")
        print(f"    Provider calls: {p.get('provider_call_count', 0)}")
        print(f"    Failed calls: {len(p.get('failed_provider_call_ids', []))}")

        # Look for failure details
        for key in ['error_message', 'exception_text', 'reason', 'reason_code']:
            if key in p:
                val = str(p[key])[:200]
                print(f"    {key}: {val}")

    elif 'terminal' in et:
        print(f"    Terminal state: {p.get('terminal_state')}")
        print(f"    User response: {p.get('user_response_hash')}")
        print(f"    Called agents: {p.get('called_agents', [])}")

print("\n" + "=" * 80)
print("\n=== SUMMARY ===")

# Final analysis
terminal_events = [e for e in events if 'terminal' in e.get('event_type', '').lower()]
if terminal_events:
    last = terminal_events[-1]
    p = last.get('payload', {})
    print(f"Terminal state: {p.get('terminal_state')}")
    print(f"Provider calls made: {p.get('provider_call_count', 0)}")
    print(f"Agents called: {p.get('called_agents', [])}")
    print(f"User response generated: {'Yes' if p.get('user_response_hash') else 'No'}")
else:
    print("No terminal event found - run may still be in progress")
