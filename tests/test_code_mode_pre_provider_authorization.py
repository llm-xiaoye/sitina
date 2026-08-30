from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from unittest.mock import patch

from sitina import cli
from sitina.orchestrator.code_mode_authority_broker import CodeModeAuthorityBrokerError
from sitina.orchestrator.true_multi_agent_runtime import (
    CanonicalStream,
    ProviderExecutor,
    TrueMultiAgentRuntimeError,
    _ControllerCapabilityIssuer,
    activate_runtime,
    pre_provider_call_identity,
    provider_call_identity_v2,
    sha256_bytes,
)
from sitina.orchestrator.true_multi_agent import RunEvidence
from sitina.orchestrator.true_multi_agent import GoalAnalysis
from sitina.journal.model import canonical_json_bytes
from sitina.runners.provider import ProviderHTTPError


class _LocalProviderHandler(BaseHTTPRequestHandler):
    requests: list[dict[str, object]] = []
    response_body = "{}"
    status_queue: list[int] = []
    malformed_response = False
    wire_case = None
    response_factory = None
    tool_turn_responses: list[dict[str, object]] = []

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        self.__class__.requests.append(json.loads(raw.decode("utf-8")))
        if self.__class__.status_queue:
            status = int(self.__class__.status_queue.pop(0))
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        dynamic_body = (
            self.__class__.response_factory(self.__class__.requests[-1])
            if callable(self.__class__.response_factory)
            else None
        )
        request_payload = self.__class__.requests[-1]
        request_tools = request_payload.get("tools")
        structured_response = any(
            isinstance(item, dict)
            and isinstance(item.get("function"), dict)
            and item["function"].get("name") == "sitina_structured_response"
            for item in (request_tools if isinstance(request_tools, list) else [])
        )
        scripted_tool_turn = self.__class__.tool_turn_responses
        if scripted_tool_turn:
            body = json.loads(json.dumps(scripted_tool_turn.pop(0)))
        elif self.__class__.malformed_response:
            body = {"choices": []}
        elif structured_response:
            structured_value = (
                dynamic_body
                if dynamic_body is not None
                else json.loads(self.__class__.response_body)
            )
            body = {
                "id": "local-pre-provider-response-1",
                "choices": [{
                    "message": {
                        "content": None,
                        "tool_calls": [{
                            "id": "local-tool-1",
                            "type": "function",
                            "function": {
                                "name": "sitina_structured_response",
                                "arguments": json.dumps(
                                    structured_value,
                                    ensure_ascii=False,
                                    separators=(",", ":"),
                                ),
                            },
                        }],
                    },
                    "finish_reason": "tool_calls",
                }],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        else:
            body = {
                "id": "local-pre-provider-response-1",
                "choices": [{
                    "message": {"content": json.dumps(dynamic_body) if dynamic_body is not None else self.__class__.response_body},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        case = self.__class__.wire_case
        if case is not None:
            message = body["choices"][0]["message"]
            if case == "missing_content":
                message.pop("content", None)
                if structured_response:
                    message.pop("tool_calls", None)
            elif case == "nonstring_content":
                message["content"] = 17
                if structured_response:
                    message.pop("tool_calls", None)
            elif case == "fenced_content":
                message["content"] = "```json\n{\"agent_id\":\"agent-atlas\"}\n```"
                if structured_response:
                    message.pop("tool_calls", None)
            elif case == "natural_content":
                message["content"] = "Here is the requested result."
                if structured_response:
                    message.pop("tool_calls", None)
            elif case == "truncated_content":
                message["content"] = '{"agent_id":"agent-atlas"'
                if structured_response:
                    message.pop("tool_calls", None)
            elif case == "empty_content":
                message["content"] = ""
            elif case == "whitespace_content":
                message["content"] = " "
            elif case == "wrong_tool_calls":
                message["tool_calls"] = {"id": "not-an-array"}
            elif case == "missing_tool_type":
                message["tool_calls"] = [{
                    "id": "local-tool-1",
                    "function": {"name": "sitina_probe", "arguments": "{}"},
                }]
            elif case == "fake_tool_type":
                message["tool_calls"] = [{
                    "id": "local-tool-1", "type": "fake",
                    "function": {"name": "sitina_probe", "arguments": "{}"},
                }]
            elif case == "missing_tool_id":
                message["tool_calls"] = [{
                    "type": "function",
                    "function": {"name": "sitina_probe", "arguments": "{}"},
                }]
            elif case == "missing_tool_function":
                message["tool_calls"] = [{"id": "local-tool-1", "type": "function"}]
            elif case == "extra_tool_key":
                message["tool_calls"] = [{
                    "id": "local-tool-1", "type": "function",
                    "function": {"name": "sitina_probe", "arguments": "{}"},
                    "extra": True,
                }]
            elif case == "tool_call_index":
                message["tool_calls"][0]["index"] = 0
            elif case == "tool_call_index_bool":
                message["tool_calls"][0]["index"] = True
            elif case == "tool_call_index_negative":
                message["tool_calls"][0]["index"] = -1
            elif case == "tool_call_index_float":
                message["tool_calls"][0]["index"] = 1.0
            elif case == "valid_tool_call":
                message["tool_calls"] = [{
                    "id": "local-tool-1", "type": "function",
                    "function": {"name": "sitina_structured_response", "arguments": "{}"},
                }]
            elif case == "usage_bool":
                body["usage"]["prompt_tokens"] = True
            elif case == "usage_string":
                body["usage"]["completion_tokens"] = "1"
            elif case == "usage_float":
                body["usage"]["total_tokens"] = 2.0
            elif case == "missing_finish_reason":
                body["choices"][0].pop("finish_reason", None)
            elif case == "finish_reason_stop":
                body["choices"][0]["finish_reason"] = "stop"
            elif case == "finish_reason_length":
                body["choices"][0]["finish_reason"] = "length"
            elif case == "finish_reason_bogus":
                body["choices"][0]["finish_reason"] = "bogus"
            elif case == "finish_reason_bool":
                body["choices"][0]["finish_reason"] = True
            elif case == "finish_reason_number":
                body["choices"][0]["finish_reason"] = 1
            else:
                raise AssertionError(f"unknown local wire case: {case}")
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args: object) -> None:
        return


class PreProviderAuthorizationProductionTests(unittest.TestCase):
    """Exercise the real launcher/host/broker/Journal/CAS transport boundary.

    The endpoint is a local non-billable HTTP server.  No Provider credential
    or external endpoint is contacted; host urllib still performs the actual
    physical request in the separately launched authority process.
    """

    def setUp(self) -> None:
        self._env = patch.dict(os.environ, {
            "SITINA_CODE_MODE_TEST_HOOKS": "1",
            "SITINA_CODE_MODE_LOCAL_PROVIDER_TEST": "1",
        })
        self._env.start()
        _LocalProviderHandler.requests = []
        _LocalProviderHandler.status_queue = []
        _LocalProviderHandler.response_body = "{}"
        _LocalProviderHandler.malformed_response = False
        _LocalProviderHandler.wire_case = None
        _LocalProviderHandler.response_factory = None
        _LocalProviderHandler.tool_turn_responses = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalProviderHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.root = Path(tempfile.mkdtemp(prefix="code-mode-pre-provider-test-"))
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        profiles = self.root / "profiles"
        profiles.mkdir()
        (profiles / "deepseek.env").write_text(
            "ANTHROPIC_BASE_URL=http://127.0.0.1:%d\n"
            "ANTHROPIC_AUTH_TOKEN=local-only\n"
            "ANTHROPIC_MODEL=deepseek-v4-pro\n" % self.server.server_port,
            encoding="utf-8",
        )
        os.chmod(profiles / "deepseek.env", 0o600)
        self.factory = None
        self.context = None
        self.journal = None

    def tearDown(self) -> None:
        if self.journal is not None:
            self.journal.close()
        if self.factory is not None:
            self.factory.close()
        self.server.shutdown()
        self.server.server_close()
        self._env.stop()

    @staticmethod
    def _root_fsm_response(request: dict[str, object]) -> dict[str, object]:
        messages = request.get("messages")
        system = str(messages[0].get("content") if isinstance(messages, list) and messages else "")
        user = str(messages[-1].get("content") if isinstance(messages, list) and messages else "")
        agent_match = re.search(r"agent_id exactly '([^']+)'", system)
        kind_match = re.search(r"kind exactly '([^']+)'", system)
        agent_id = agent_match.group(1) if agent_match else "agent-atlas"
        kind = kind_match.group(1) if kind_match else "proposal"
        if kind == "review":
            return {
                "agent_id": agent_id,
                "kind": "review",
                "verdict": "approved",
                "score": 90,
                "reason": "the proposal satisfies the fixed local contract",
                "defects": [],
            }
        if "Analyze this goal" in user:
            return {
                "agent_id": agent_id,
                "kind": "proposal",
                "complexity": "simple",
                "risk_level": "low",
                "protocols": ["proposal"],
                "task_graph": ["produce and review one bounded proposal"],
                "proposal_count": 1,
                "domain_capability": None,
                "requires_rework": False,
                "requires_conflict": False,
                "requires_handoff_reject": False,
                "requires_reassignment": False,
                "requires_provider_unknown": False,
                "rationale": "local root FSM production-path fixture",
            }
        return {
            "agent_id": agent_id,
            "kind": "proposal",
            "summary": "a bounded proposal",
            "approach": "perform the bounded operation and verify its result",
            "risks": ["the local fixture has no external side effect"],
            "assumptions": ["the reviewed contract remains unchanged"],
            "acceptance_checks": ["the result is independently reviewed"],
        }

    def test_real_root_fsm_requires_discovery_proposal_review_and_selection_order(self) -> None:
        """The real host path cannot skip proposal acceptance with a review call."""
        _runtime_home, multi, run_id, conversation_id, _generation, authorization, activation = self._runtime()
        self.journal = self.context.open_runtime_writer()
        _LocalProviderHandler.response_factory = self._root_fsm_response
        executor = ProviderExecutor(
            _runtime_home,
            self.context,
            run_id,
            multi.policy_hash,
            multi.policy,
            activation,
            self.journal,
            self.context.open_cas(),
            client_override=None,
            pre_provider_authorization=authorization,
        )
        evidence = RunEvidence(
            run_id, "root FSM local test", sha256_bytes(b"root FSM local test"), multi.policy_hash,
        )
        run_stream = CanonicalStream(
            self.journal, run_id, f"run/{run_id}", multi.policy_hash,
        )
        discovery_agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
        discovery = executor.call(
            discovery_agent,
            task_id="goal-discovery",
            kind="proposal",
            root_phase="discovery/controller",
            system_prompt=(
                f"agent_id exactly '{discovery_agent.agent_id}' kind exactly 'proposal'"
            ),
            user_prompt="Analyze this goal",
            input_context={},
            validate=lambda _value: None,
        )
        evidence.calls.append(discovery)
        analysis = GoalAnalysis(
            complexity="simple", risk_level="low", protocols=("proposal",),
            task_graph=("produce and review one bounded proposal",), proposal_count=1,
            domain_capability=None, requires_rework=False, requires_conflict=False,
            requires_handoff_reject=False, requires_reassignment=False,
            requires_provider_unknown=False, rationale="root FSM local test",
        )
        winner, _winner_agent, proposals, _decision = multi._proposal_and_review(
            self.journal, run_stream, executor, evidence, analysis, {},
        )
        self.assertTrue(winner.output_ref)
        self.assertEqual(len(proposals), 1)
        self.assertEqual(executor.physical_send_total(), 3)
        self.assertEqual(len(_LocalProviderHandler.requests), 3)
        # Once the authenticated selection has completed, a root-domain
        # permit is closed.  A legal-looking next call must not reach HTTP.
        with self.assertRaises(TrueMultiAgentRuntimeError):
            executor.call(
                discovery_agent,
                task_id="review-1", kind="review",
                root_phase="review/selection", system_prompt="system",
                user_prompt="post-selection root call", input_context={},
                validate=lambda _value: None,
            )
        self.assertEqual(len(_LocalProviderHandler.requests), 3)

    def _runtime(self):
        with patch.object(cli, "SITINA_HOME", self.root):
            runtime_home, self.factory, multi = cli._build_code_mode_runtime(
                self.workspace,
                state_root=self.root / "state",
                provider=None,
                session_instance_id="pre-provider-test-session",
            )
        self.context = self.factory(runtime_home)
        run_id = "pre-provider-test-run"
        conversation_id = "pre-provider-test-conversation"
        generation = self.context.identity.epoch_root
        self.journal = self.context.open_runtime_writer()
        stream = CanonicalStream(
            self.journal, run_id, f"run/{run_id}", self.context.identity.genesis_hash,
        )
        controls = {
            "session_instance_id": self.context.session_instance_id,
            "conversation_session_id": conversation_id,
            "conversation_turn_index": 0,
            "code_mode_authorization": {
                "allowed": True,
                "session_id": conversation_id,
                "session_instance_id": self.context.session_instance_id,
                "generation": generation,
            },
        }
        stream.append(
            "run-created",
            ({
                "schema": "TRUE_MULTI_AGENT_RUN_CREATED_V1",
                "event_type": "run.created",
                "run_id": run_id,
                "generation": generation,
                "acceptance_controls": controls,
            },),
            actor="pre-provider-test",
        )
        self.journal.close()
        self.journal = None
        authorization = self.context.issue_pre_provider_authorization(
            session_id=conversation_id,
            turn_index=0,
            run_id=run_id,
            run_attempt=1,
            generation=generation,
            provider_profile="deepseek",
            provider_model="deepseek-v4-pro",
        )
        activation = activate_runtime(
            runtime_home,
            self.context,
            self.context.open_cas(),
            multi.registry,
            multi.policy,
            run_id=run_id,
            session_id=conversation_id,
            pre_provider_authorization=authorization,
            offline=False,
            source_root=Path(__file__).resolve().parents[1],
        )
        return runtime_home, multi, run_id, conversation_id, generation, authorization, activation

    def _seed_root_schedule(self, multi, executor, run_id: str, journal):
        """Create the authenticated discovery slot used by direct transport tests.

        ProviderExecutor deliberately refuses a root call without the
        scheduler/dispatch facts that production TrueMulti writes before
        activation.  These tests exercise the real dedicated Journal path,
        so the fixture uses the production scheduler rather than planting a
        caller-built binding in the executor.
        """
        evidence = RunEvidence(
            run_id, "pre-provider test", sha256_bytes(b"pre-provider test"), multi.policy_hash,
        )
        stream = CanonicalStream(
            journal, run_id, f"run/{run_id}", multi.policy_hash,
        )
        _decision, agents = multi._schedule(
            journal, stream, evidence,
            task_id="goal-discovery",
            required_capabilities=(),
            slots=1,
            candidate_tasks=("goal-discovery",),
            root_executor=executor,
        )
        return agents[0]

    def test_real_cli_host_transport_sends_with_pre_provider_authorization(self) -> None:
        runtime_home, multi, run_id, _conversation, _generation, authorization, activation = self._runtime()
        self.journal = self.context.open_runtime_writer()
        executor = ProviderExecutor(
            runtime_home,
            self.context,
            run_id,
            multi.policy_hash,
            multi.policy,
            activation,
            self.journal,
            self.context.open_cas(),
            client_override=None,
            pre_provider_authorization=authorization,
        )
        agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
        _LocalProviderHandler.wire_case = "tool_call_index"
        _LocalProviderHandler.response_body = json.dumps({"agent_id": agent.agent_id, "kind": "proposal"})
        result = executor.call(
            agent,
            task_id="goal-discovery",
            kind="proposal",
            root_phase="discovery/controller",
            system_prompt="system",
            user_prompt="user",
            input_context={},
            validate=lambda value: None,
        )
        self.assertEqual(result.provider_request_id, "local-pre-provider-response-1")
        self.assertEqual(executor.physical_send_total(), 1)
        self.assertEqual(len(_LocalProviderHandler.requests), 1)
        wire_request = _LocalProviderHandler.requests[0]
        self.assertEqual(wire_request["tools"][0]["function"]["name"], "sitina_structured_response")
        self.assertEqual(wire_request["tool_choice"], {
            "type": "function",
            "function": {"name": "sitina_structured_response"},
        })
        self.assertEqual(wire_request["thinking"], {"type": "disabled"})
        self.assertFalse("response_format" in wire_request)
        self.assertFalse("parallel_tool_calls" in wire_request)
        receipts = executor.provider_transport_receipts()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["authorization_kind"], "pre-provider")
        self.assertTrue(str(receipts[0]["authorization_id"]).startswith("pre-provider:"))

    def test_real_host_structured_tool_call_accepts_explicit_empty_content(self) -> None:
        runtime_home, multi, run_id, _conversation, _generation, authorization, activation = self._runtime()
        self.journal = self.context.open_runtime_writer()
        executor = ProviderExecutor(
            runtime_home,
            self.context,
            run_id,
            multi.policy_hash,
            multi.policy,
            activation,
            self.journal,
            self.context.open_cas(),
            client_override=None,
            pre_provider_authorization=authorization,
        )
        agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
        _LocalProviderHandler.wire_case = "empty_content"
        _LocalProviderHandler.response_body = json.dumps({"agent_id": agent.agent_id, "kind": "proposal"})
        result = executor.call(
            agent,
            task_id="goal-discovery",
            kind="proposal",
            root_phase="discovery/controller",
            system_prompt="system",
            user_prompt="user",
            input_context={},
            validate=lambda value: None,
        )
        self.assertEqual(result.provider_request_id, "local-pre-provider-response-1")
        self.assertEqual(len(_LocalProviderHandler.requests), 1)
        self.assertEqual(executor.physical_send_total(), 1)
        self.assertEqual(len(executor.provider_transport_receipts()), 1)
        self.assertEqual(executor.provider_transport_receipts()[0]["finish_reason"], "tool_calls")

    def test_real_host_converts_neutral_tools_to_openai_wire(self) -> None:
        _runtime_home, multi, run_id, conversation, generation, authorization, _activation = self._runtime()
        self.journal = self.context.open_runtime_writer()
        executor = ProviderExecutor(
            self.root, self.context, run_id, multi.policy_hash, multi.policy,
            _activation, self.journal, self.context.open_cas(),
            client_override=None, pre_provider_authorization=authorization,
        )
        agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
        task_id = "goal-discovery"
        effect_id = "neutral-tool-wire-1"
        binding = executor._pre_provider_call_binding(
            kind="proposal", agent=agent, ordinal=1, task_id=task_id,
            input_context={}, root_phase="discovery/controller",
        )
        executor.transport.root_fact_publisher("dispatch", binding, effect_id, None)
        ledger, capability = self.context._authoritative_transport_ledger()
        ledger.bind_pre_provider_authorization(authorization)
        tools = [{
            "name": "read_fact",
            "description": "Read one fact.",
            "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
        }]
        _LocalProviderHandler.response_body = json.dumps({"ok": True})
        result = ledger.send(
            capability,
            run_id=run_id,
            attempt=1,
            session_instance_id=self.context.session_instance_id,
            conversation_session_id=conversation,
            turn_index=0,
            generation=generation,
            effect_attempt_id=effect_id,
            provider_call_id=effect_id,
            provider_profile="deepseek",
            provider_model="deepseek-v4-pro",
            system_prompt="system",
            user_prompt="read it",
            system_prompt_hash=sha256_bytes(b"system"),
            user_prompt_hash=sha256_bytes(b"read it"),
            tools=tools,
            tools_hash=sha256_bytes(canonical_json_bytes(tools)),
            max_tokens=8,
            timeout=1,
            phase=binding["phase"],
            role=binding["role"],
            call_index=binding["call_index"],
            agent_id=binding["agent_id"],
            task_id=binding["task_id"],
            dispatch_commitment=binding["dispatch_commitment"],
            scheduling_task_id=binding["scheduling_task_id"],
            scheduling_decision_id=binding["scheduling_decision_id"],
            scheduling_decision_commitment=binding["scheduling_decision_commitment"],
            dispatch_command_id=binding["dispatch_command_id"],
            dispatch_command_commitment=binding["dispatch_command_commitment"],
            selected_agent_id=binding["selected_agent_id"],
            slot=binding["slot"],
            predecessor_identity=binding["predecessor_identity"],
            pre_provider_call_identity=binding["pre_provider_call_identity"],
        )
        self.assertEqual(len(_LocalProviderHandler.requests), 1)
        self.assertEqual(_LocalProviderHandler.requests[0]["tools"], [{
            "type": "function",
            "function": {
                "name": "read_fact",
                "description": "Read one fact.",
                "parameters": tools[0]["input_schema"],
            },
        }])
        self.assertNotIn("response_format", _LocalProviderHandler.requests[0])
        self.assertEqual(result["receipt"]["provider_profile"], "deepseek")

    def test_real_host_converts_neutral_multiturn_messages_to_openai_wire(self) -> None:
        _runtime_home, multi, run_id, conversation, generation, authorization, _activation = self._runtime()
        self.journal = self.context.open_runtime_writer()
        executor = ProviderExecutor(
            self.root, self.context, run_id, multi.policy_hash, multi.policy,
            _activation, self.journal, self.context.open_cas(),
            client_override=None, pre_provider_authorization=authorization,
        )
        agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
        ledger, capability = self.context._authoritative_transport_ledger()
        effect_one = "neutral-multiturn-1"
        effect_two = "neutral-multiturn-2"
        _LocalProviderHandler.tool_turn_responses = [{
            "id": "local-tool-turn-1",
            "choices": [{
                "finish_reason": "tool_calls",
                "message": {
                    "content": None,
                    "tool_calls": [{
                        "id": "call-read-1", "type": "function",
                        "function": {
                            "name": "read_fact",
                            "arguments": '{"path":"/tmp/f"}',
                        },
                    }],
                },
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }, {
            "id": "local-tool-turn-2",
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": "done"},
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }]
        tools = [{
            "name": "read_fact", "description": "Read one fact.",
            "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
        }]

        def send_turn(effect_id: str, binding: Mapping[str, Any], messages: list[dict[str, Any]]) -> dict[str, Any]:
            return ledger.send(
                capability, run_id=run_id, attempt=1,
                session_instance_id=self.context.session_instance_id,
                conversation_session_id=conversation, turn_index=0, generation=generation,
                effect_attempt_id=effect_id, provider_call_id=effect_id,
                provider_profile="deepseek", provider_model="deepseek-v4-pro",
                system_prompt="system", user_prompt="read it",
                system_prompt_hash=sha256_bytes(b"system"), user_prompt_hash=sha256_bytes(b"read it"),
                messages=messages,
                messages_hash=sha256_bytes(canonical_json_bytes(messages)), tools=tools,
                tools_hash=sha256_bytes(canonical_json_bytes(tools)), structured_response=False,
                structured_response_tool_name=None, max_tokens=8, timeout=1,
                phase=binding["phase"], role=binding["role"], call_index=binding["call_index"],
                agent_id=binding["agent_id"], task_id=binding["task_id"],
                dispatch_commitment=binding["dispatch_commitment"],
                scheduling_task_id=binding["scheduling_task_id"],
                scheduling_decision_id=binding["scheduling_decision_id"],
                scheduling_decision_commitment=binding["scheduling_decision_commitment"],
                dispatch_command_id=binding["dispatch_command_id"],
                dispatch_command_commitment=binding["dispatch_command_commitment"],
                selected_agent_id=binding["selected_agent_id"], slot=binding["slot"],
                predecessor_identity=binding["predecessor_identity"],
                pre_provider_call_identity=binding["pre_provider_call_identity"],
            )

        binding_one = executor._pre_provider_call_binding(
            kind="proposal", agent=agent, ordinal=1, task_id="goal-discovery",
            input_context={}, root_phase="discovery/controller",
        )
        executor.transport.root_fact_publisher("dispatch", binding_one, effect_one, None)
        first = send_turn(effect_one, binding_one, [{"role": "user", "content": "read it"}])
        executor.transport.root_fact_publisher("settled", binding_one, effect_one, first["receipt"])
        executor.transport.root_fact_publisher(
            "result_accepted", binding_one, effect_one, {
                "provider_response_id": first["receipt"]["provider_response_id"],
                "response_receipt_hash": sha256_bytes(canonical_json_bytes(first["receipt"])),
                "output_ref": "cas:" + "a" * 64,
                "output_hash": "b" * 64,
                "task_attempt_id": "task-attempt-neutral-multiturn",
            },
        )
        run_stream = CanonicalStream(self.journal, run_id, f"run/{run_id}", multi.policy_hash)
        evidence = RunEvidence(run_id, "neutral multiturn", sha256_bytes(b"neutral multiturn"), multi.policy_hash)
        _decision, agents = multi._schedule(
            self.journal, run_stream, evidence, task_id="proposal-competition", required_capabilities=(),
            slots=1, candidate_tasks=("proposal-competition",), root_executor=executor,
        )
        agent_two = agents[0]
        binding_two = executor._pre_provider_call_binding(
            kind="proposal", agent=agent_two, ordinal=2, task_id="proposal-competition",
            input_context={}, root_phase="proposal/planner/candidate",
        )
        executor.transport.root_fact_publisher("dispatch", binding_two, effect_two, None)
        second_messages = [
            {"role": "user", "content": "read it"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call-read-1", "name": "read_fact", "arguments": {"path": "/tmp/f"},
            }]},
            {"role": "tool", "tool_call_id": "call-read-1", "name": "read_fact", "content": "fact", "is_error": False},
        ]
        second = send_turn(effect_two, binding_two, second_messages)
        self.assertEqual(first["tool_calls"], [{"id": "call-read-1", "name": "read_fact", "arguments": {"path": "/tmp/f"}}])
        self.assertEqual(second["completion_text"], "done")
        self.assertEqual(_LocalProviderHandler.requests[1]["messages"], [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "read it"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call-read-1", "type": "function",
                "function": {"name": "read_fact", "arguments": '{"path":"/tmp/f"}'},
            }]},
            {"role": "tool", "tool_call_id": "call-read-1", "content": "fact"},
        ])

    def test_root_pre_provider_permit_rejects_forge_run_and_bad_phase_before_http(self) -> None:
        _runtime_home, _multi, run_id, _conversation, _generation, authorization, _activation = self._runtime()
        ledger, capability = self.context._authoritative_transport_ledger()
        ledger.bind_pre_provider_authorization(authorization)
        common = {
            "effect_attempt_id": "pre-provider-negative-effect",
            "provider_profile": "deepseek",
            "provider_model": "deepseek-v4-pro",
            "system_prompt": "system",
            "user_prompt": "user",
            "system_prompt_hash": sha256_bytes(b"system"),
            "user_prompt_hash": sha256_bytes(b"user"),
            "tools": [],
            "tools_hash": sha256_bytes(b"[]"),
            "max_tokens": 8,
            "timeout": 1,
            "phase": "discovery/controller",
            "role": "controller",
            "call_index": 1,
            "pre_provider_call_identity": pre_provider_call_identity(
                session_instance_id=self.context.session_instance_id,
                conversation_session_id=authorization["conversation_session_id"],
                turn_index=0,
                run_id=run_id,
                run_attempt=1,
                phase="discovery/controller",
                role="controller",
                call_index=1,
                provider_profile="deepseek",
                provider_model="deepseek-v4-pro",
            ),
        }
        with self.assertRaises(CodeModeAuthorityBrokerError):
            ledger.send(capability, run_id=f"forge-exec-{run_id}-1", **common)
        bad_phase = dict(common)
        bad_phase["run_id"] = run_id
        bad_phase["phase"] = "caller-selected-phase"
        bad_phase["pre_provider_call_identity"] = "not-the-derived-call"
        with self.assertRaises(CodeModeAuthorityBrokerError):
            ledger.send(capability, **bad_phase)
        self.assertEqual(_LocalProviderHandler.requests, [])

    def test_pre_provider_handle_scope_is_one_shot(self) -> None:
        _runtime_home, _multi, run_id, conversation, generation, _authorization, _activation = self._runtime()
        with self.assertRaises(CodeModeAuthorityBrokerError):
            self.context.issue_pre_provider_authorization(
                session_id=conversation,
                turn_index=0,
                run_id=run_id,
                run_attempt=1,
                generation=generation,
                provider_profile="deepseek",
                provider_model="deepseek-v4-pro",
            )

    def test_forged_pre_provider_handle_is_rejected_by_pinned_controller_key(self) -> None:
        _runtime_home, _multi, run_id, conversation, generation, _authorization, _activation = self._runtime()
        forged_issuer = _ControllerCapabilityIssuer()
        forged = forged_issuer.mint_pre_provider(
            session_instance_id=self.context.session_instance_id,
            conversation_session_id=conversation,
            turn_index=0,
            run_id=run_id,
            run_attempt=1,
            generation=generation,
            provider_profile="deepseek",
            provider_model="deepseek-v4-pro",
            issued_at=1,
            expires_at=2_000_000_000,
        )
        broker = self.context._broker_client
        session = self.context._broker_session
        self.assertIsNotNone(broker)
        self.assertIsNotNone(session)
        with self.assertRaises(CodeModeAuthorityBrokerError):
            broker._rpc({
                "method": "issue_pre_provider_authorization",
                "session": session,
                "capability": forged.as_mapping(),
            })
        self.assertEqual(_LocalProviderHandler.requests, [])

    def test_pre_provider_provider_binding_mismatch_is_rejected_before_http(self) -> None:
        _runtime_home, _multi, run_id, _conversation, _generation, authorization, _activation = self._runtime()
        ledger, capability = self.context._authoritative_transport_ledger()
        ledger.bind_pre_provider_authorization(authorization)
        phase = "discovery/controller"
        role = "controller"
        call_index = 1
        request = {
            "effect_attempt_id": "pre-provider-provider-mismatch",
            "provider_profile": "deepseek",
            "provider_model": "wrong-model",
            "system_prompt": "system",
            "user_prompt": "user",
            "system_prompt_hash": sha256_bytes(b"system"),
            "user_prompt_hash": sha256_bytes(b"user"),
            "tools": [],
            "tools_hash": sha256_bytes(b"[]"),
            "max_tokens": 8,
            "timeout": 1,
            "phase": phase,
            "role": role,
            "call_index": call_index,
            "pre_provider_call_identity": pre_provider_call_identity(
                session_instance_id=self.context.session_instance_id,
                conversation_session_id=authorization["conversation_session_id"],
                turn_index=0,
                run_id=run_id,
                run_attempt=1,
                phase=phase,
                role=role,
                call_index=call_index,
                provider_profile="deepseek",
                provider_model=authorization["provider_model"],
            ),
        }
        with self.assertRaises(CodeModeAuthorityBrokerError):
            ledger.send(capability, run_id=run_id, **request)
        self.assertEqual(_LocalProviderHandler.requests, [])

    def test_pre_provider_call_index_is_contiguous_and_one_use(self) -> None:
        _runtime_home, _multi, run_id, _conversation, _generation, authorization, _activation = self._runtime()
        ledger, capability = self.context._authoritative_transport_ledger()
        broker = self.context._broker_client
        session = self.context._broker_session
        self.assertIsNotNone(broker)
        self.assertIsNotNone(session)
        ledger.bind_pre_provider_authorization(authorization)
        phase = "discovery/controller"
        role = "controller"

        def values(call_index: int) -> dict[str, object]:
            return {
                "authorization_id": authorization["authorization_id"],
                "authorization_kind": "pre-provider",
                "run_id": run_id,
                "attempt": 1,
                "session_instance_id": authorization["session_instance_id"],
                "conversation_session_id": authorization["conversation_session_id"],
                "turn_index": 0,
                "generation": authorization["generation"],
                "effect_attempt_id": "pre-provider-index-%d" % call_index,
                "provider_call_id": "pre-provider-index-%d" % call_index,
                "provider_profile": "deepseek",
                "provider_model": "deepseek-v4-pro",
                "system_prompt": "system",
                "user_prompt": "user",
                "system_prompt_hash": sha256_bytes(b"system"),
                "user_prompt_hash": sha256_bytes(b"user"),
                "tools": [],
                "tools_hash": sha256_bytes(b"[]"),
                "max_tokens": 8,
                "timeout": 1,
                "phase": phase,
                "role": role,
                "call_index": call_index,
                # The transport-broker test exercises the same authenticated
                # root transition as production.  Seed its first dispatch
                # through the typed producer entry below rather than relying
                # on a caller-built request to stand in for Journal facts.
                "agent_id": "controller-agent",
                "task_id": "index-test-task",
                "dispatch_commitment": "d" * 64,
                "scheduling_task_id": "index-test-task",
                "scheduling_decision_id": "index-test-decision",
                "scheduling_decision_commitment": "c" * 64,
                "dispatch_command_id": "index-test-dispatch-command",
                "dispatch_command_commitment": "d" * 64,
                "selected_agent_id": "controller-agent",
                "slot": 1,
                "predecessor_identity": "root",
                "pre_provider_call_identity": provider_call_identity_v2(
                    session_instance_id=self.context.session_instance_id,
                    conversation_session_id=authorization["conversation_session_id"],
                    turn_index=0,
                    run_id=run_id,
                    run_attempt=1,
                    agent_id="controller-agent",
                    task_id="index-test-task",
                    dispatch_commitment="d" * 64,
                    predecessor_identity="root",
                    phase=phase,
                    role=role,
                    call_index=call_index,
                    provider_profile="deepseek",
                    provider_model="deepseek-v4-pro",
                ),
            }

        # A call-index gap is rejected before any physical provider request.
        with self.assertRaises(CodeModeAuthorityBrokerError):
            broker._transport_begin(
                session,
                capability._token,
                authorization["authorization_id"],
                values(2),
            )
        skipped_proposal = values(2)
        skipped_proposal["phase"] = "review/selection"
        skipped_proposal["pre_provider_call_identity"] = pre_provider_call_identity(
            session_instance_id=self.context.session_instance_id,
            conversation_session_id=authorization["conversation_session_id"],
            turn_index=0,
            run_id=run_id,
            run_attempt=1,
            phase="review/selection",
            role=role,
            call_index=2,
            provider_profile="deepseek",
            provider_model="deepseek-v4-pro",
        )
        with self.assertRaises(CodeModeAuthorityBrokerError):
            broker._transport_begin(
                session,
                capability._token,
                authorization["authorization_id"],
                skipped_proposal,
            )
        root_binding = values(1)
        root_journal = self.context.open_runtime_writer()
        try:
            root_stream = CanonicalStream(
                root_journal, run_id, f"run/{run_id}", self.context.identity.genesis_hash,
            )
            root_stream.append_root_producer_fact(
                {
                    "schema": "AGENT_SCHEDULING_DECISION_V1",
                    "event_type": "scheduling.decision",
                    "purpose": "code-mode-agent-scheduling",
                    "purpose_class": "code-mode-agent-scheduling-decision",
                    "run_id": run_id,
                    "session_instance_id": authorization["session_instance_id"],
                    "conversation_session_id": authorization["conversation_session_id"],
                    "turn_index": 0,
                    "generation": authorization["generation"],
                    "run_attempt": 1,
                    "decision_id": "index-test-decision",
                    "decision_commitment": "c" * 64,
                    "task_id": "index-test-task",
                    "phase": phase,
                    "selected_agents": ["controller-agent"],
                    "requested_slots": 1,
                    "required_capabilities": [],
                    "decision": {
                        "decision_id": "index-test-decision",
                        "decision_commitment": "c" * 64,
                    },
                },
                actor="pre-provider-index-test",
                producer_role="root_scheduling",
                command_id="root-index-scheduling",
            )
            root_stream.append_root_producer_fact(
                {
                    "schema": "DISPATCH_COMMAND_ACCEPTED_V1",
                    "event_type": "dispatch.command.accepted",
                    "purpose": "code-mode-dispatch-command",
                    "purpose_class": "code-mode-dispatch-command-accepted",
                    "run_id": run_id,
                    "session_instance_id": authorization["session_instance_id"],
                    "conversation_session_id": authorization["conversation_session_id"],
                    "turn_index": 0,
                    "generation": authorization["generation"],
                    "run_attempt": 1,
                    "decision_id": "index-test-decision",
                    "decision_commitment": "c" * 64,
                    "dispatch_command_id": "index-test-dispatch-command",
                    "dispatch_commitment": "d" * 64,
                    "task_id": "index-test-task",
                    "phase": phase,
                    "selected_agents": ["controller-agent"],
                    "requested_slots": 1,
                    "required_capabilities": [],
                    "state": "ACCEPTED",
                },
                actor="pre-provider-index-test",
                producer_role="root_dispatch_acceptance",
                command_id="index-test-dispatch-command",
            )
            root_stream.append_root_producer_fact(
                {
                    "schema": "CODE_MODE_ROOT_DISPATCH_FACT_V1",
                    "event_type": "code-mode.root-call-dispatched",
                    "purpose": "code-mode-root-call-dispatch",
                    "purpose_class": "code-mode-root-call-dispatch",
                    "run_id": run_id,
                    "session_instance_id": authorization["session_instance_id"],
                    "conversation_session_id": authorization["conversation_session_id"],
                    "turn_index": 0,
                    "generation": authorization["generation"],
                    "run_attempt": 1,
                    "agent_id": root_binding["agent_id"],
                    "task_id": root_binding["task_id"],
                    "role": root_binding["role"],
                    "phase": root_binding["phase"],
                    "call_index": root_binding["call_index"],
                    "dispatch_commitment": root_binding["dispatch_commitment"],
                    "predecessor_identity": root_binding["predecessor_identity"],
                    "pre_provider_call_identity": root_binding["pre_provider_call_identity"],
                    "provider_profile": root_binding["provider_profile"],
                    "provider_model": root_binding["provider_model"],
                    "provider_call_id": root_binding["effect_attempt_id"],
                    "scheduling_task_id": root_binding["scheduling_task_id"],
                    "scheduling_decision_id": root_binding["scheduling_decision_id"],
                    "scheduling_decision_commitment": root_binding["scheduling_decision_commitment"],
                    "dispatch_command_id": root_binding["dispatch_command_id"],
                    "dispatch_command_commitment": root_binding["dispatch_command_commitment"],
                    "selected_agent_id": root_binding["selected_agent_id"],
                    "slot": root_binding["slot"],
                    "state": "DISPATCHED",
                },
                actor="pre-provider-index-test",
                producer_role="root_dispatch",
                command_id="root-index-dispatch",
            )
        finally:
            root_journal.close()
        permit = broker._transport_begin(
            session,
            capability._token,
            authorization["authorization_id"],
            values(1),
        )
        self.assertTrue(permit)
        # Reusing the same deterministic identity is not a second root call.
        with self.assertRaises(CodeModeAuthorityBrokerError):
            broker._transport_begin(
                session,
                capability._token,
                authorization["authorization_id"],
                values(1),
            )
        self.assertEqual(_LocalProviderHandler.requests, [])

    def test_real_host_settled_provider_call_replays_without_second_http(self) -> None:
        runtime_home, multi, run_id, _conversation, _generation, authorization, activation = self._runtime()
        self.journal = self.context.open_runtime_writer()
        executor = ProviderExecutor(
            runtime_home, self.context, run_id, multi.policy_hash, multi.policy,
            activation, self.journal, self.context.open_cas(),
            client_override=None, pre_provider_authorization=authorization,
        )
        agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
        _LocalProviderHandler.response_body = json.dumps({"agent_id": agent.agent_id, "kind": "proposal"})
        captured: list[tuple[object, str]] = []
        results: list[dict[str, object]] = []
        original_send_once = executor.transport.send_once

        def capture(request, effect_attempt_id):
            captured.append((request, effect_attempt_id))
            result = original_send_once(request, effect_attempt_id)
            results.append(result)
            return result

        executor.transport.send_once = capture  # type: ignore[method-assign]
        executor.call(
            agent, task_id="goal-discovery", kind="proposal",
            root_phase="discovery/controller",
            system_prompt="system", user_prompt="user", input_context={},
            validate=lambda value: None,
        )
        self.assertEqual(len(captured), 1)
        request, effect_attempt_id = captured[0]
        second = original_send_once(request, effect_attempt_id)
        first = results[0]
        for key in ("raw_text", "metadata", "effect_attempt_id"):
            self.assertEqual(first[key], second[key])
        self.assertEqual(len(_LocalProviderHandler.requests), 1)
        self.assertEqual(executor.transport.physical_send_count, 1)
        self.assertEqual(len(executor.provider_transport_receipts()), 1)
        self.assertEqual(results[0]["metadata"]["finish_reason"], "tool_calls")
        self.assertTrue(results[0]["metadata"]["structured_response"])
        self.assertEqual(executor.provider_transport_receipts()[0]["finish_reason"], "tool_calls")

    def test_real_host_retryable_http_reuses_one_logical_provider_call(self) -> None:
        _LocalProviderHandler.status_queue = [503]
        runtime_home, multi, run_id, _conversation, _generation, authorization, activation = self._runtime()
        self.journal = self.context.open_runtime_writer()
        executor = ProviderExecutor(
            runtime_home, self.context, run_id, multi.policy_hash, multi.policy,
            activation, self.journal, self.context.open_cas(),
            client_override=None, pre_provider_authorization=authorization,
        )
        agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
        _LocalProviderHandler.response_body = json.dumps({"agent_id": agent.agent_id, "kind": "proposal"})
        executor.transport.max_retries = 1
        executor.call(
            agent, task_id="goal-discovery", kind="proposal",
            root_phase="discovery/controller",
            system_prompt="system", user_prompt="user", input_context={},
            validate=lambda value: None,
        )
        self.assertEqual(executor.transport.retry_count, 1)
        self.assertEqual(len(_LocalProviderHandler.requests), 2)
        self.assertEqual(executor.transport.physical_send_count, 2)

    def test_real_host_retry_budget_exhaustion_forbids_next_http(self) -> None:
        """A retryable response at the hard cap cannot mint another permit."""
        _LocalProviderHandler.status_queue = [503, 503]
        runtime_home, multi, run_id, _conversation, _generation, authorization, activation = self._runtime()
        self.journal = self.context.open_runtime_writer()
        executor = ProviderExecutor(
            runtime_home, self.context, run_id, multi.policy_hash, multi.policy,
            activation, self.journal, self.context.open_cas(),
            client_override=None, pre_provider_authorization=authorization,
        )
        agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
        captured: list[tuple[object, str]] = []
        original_send_once = executor.transport.send_once

        def capture(request, effect_attempt_id):
            captured.append((request, effect_attempt_id))
            return original_send_once(request, effect_attempt_id)

        executor.transport.send_once = capture  # type: ignore[method-assign]
        executor.transport.max_retries = 1
        with self.assertRaises(ProviderHTTPError) as raised:
            executor.call(
                agent, task_id="goal-discovery", kind="proposal",
                root_phase="discovery/controller", system_prompt="system", user_prompt="user",
                input_context={}, validate=lambda value: None,
            )
        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(len(_LocalProviderHandler.requests), 2)
        self.assertEqual(executor.transport.physical_send_count, 2)
        request, effect_attempt_id = captured[0]
        with self.assertRaises(TrueMultiAgentRuntimeError):
            original_send_once(request, effect_attempt_id)
        self.assertEqual(len(_LocalProviderHandler.requests), 2)

    def test_malformed_200_is_unknown_and_never_retried(self) -> None:
        _LocalProviderHandler.malformed_response = True
        runtime_home, multi, run_id, _conversation, _generation, authorization, activation = self._runtime()
        self.journal = self.context.open_runtime_writer()
        executor = ProviderExecutor(
            runtime_home, self.context, run_id, multi.policy_hash, multi.policy,
            activation, self.journal, self.context.open_cas(),
            client_override=None, pre_provider_authorization=authorization,
        )
        agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
        executor.transport.max_retries = 3
        with self.assertRaises(TrueMultiAgentRuntimeError):
            executor.call(
                agent, task_id="goal-discovery", kind="proposal",
                root_phase="discovery/controller", system_prompt="system",
                user_prompt="user", input_context={}, validate=lambda value: None,
            )
        # A response that reached the local HTTP endpoint but cannot be
        # parsed as a provider completion is OUTCOME_UNKNOWN at the host;
        # retry policy must not turn it into another physical send.
        self.assertEqual(len(_LocalProviderHandler.requests), 1)

    def test_strict_wire_schema_rejects_invalid_200_without_replay_send(self) -> None:
        """The host never coerces malformed response fields into a receipt."""
        cases = (
            "missing_content", "nonstring_content", "fenced_content",
            "natural_content", "truncated_content", "whitespace_content", "wrong_tool_calls",
            "missing_tool_type", "fake_tool_type", "missing_tool_id",
            "missing_tool_function", "extra_tool_key",
            "tool_call_index_bool", "tool_call_index_negative", "tool_call_index_float",
            "usage_bool", "usage_string", "usage_float",
            "missing_finish_reason", "finish_reason_stop", "finish_reason_length",
            "finish_reason_bogus", "finish_reason_bool", "finish_reason_number",
        )
        for case in cases:
            with self.subTest(case=case):
                # Each case gets a fresh Code Mode state root and host session;
                # the HTTP server remains the same non-billable local endpoint.
                self.root = Path(tempfile.mkdtemp(prefix="code-mode-wire-case-"))
                self.workspace = self.root / "workspace"
                self.workspace.mkdir()
                profiles = self.root / "profiles"
                profiles.mkdir()
                (profiles / "deepseek.env").write_text(
                    "ANTHROPIC_BASE_URL=http://127.0.0.1:%d\n"
                    "ANTHROPIC_AUTH_TOKEN=local-only\n"
                    "ANTHROPIC_MODEL=deepseek-v4-pro\n" % self.server.server_port,
                    encoding="utf-8",
                )
                os.chmod(profiles / "deepseek.env", 0o600)
                _LocalProviderHandler.requests = []
                _LocalProviderHandler.wire_case = case
                runtime_home, multi, run_id, _conversation, _generation, authorization, activation = self._runtime()
                self.journal = self.context.open_runtime_writer()
                executor = ProviderExecutor(
                    runtime_home, self.context, run_id, multi.policy_hash, multi.policy,
                    activation, self.journal, self.context.open_cas(),
                    client_override=None, pre_provider_authorization=authorization,
                )
                agent = self._seed_root_schedule(multi, executor, run_id, self.journal)
                captured: list[tuple[object, str]] = []
                original_send_once = executor.transport.send_once

                def capture(request, effect_attempt_id):
                    captured.append((request, effect_attempt_id))
                    return original_send_once(request, effect_attempt_id)

                executor.transport.send_once = capture  # type: ignore[method-assign]
                with self.assertRaises(TrueMultiAgentRuntimeError):
                    executor.call(
                        agent, task_id="goal-discovery", kind="proposal",
                        root_phase="discovery/controller", system_prompt="system",
                        user_prompt="user", input_context={}, validate=lambda value: None,
                    )
                self.assertEqual(len(_LocalProviderHandler.requests), 1)
                self.assertEqual(len(captured), 1)
                self.assertEqual(executor.provider_transport_receipts(), ())
                with self.assertRaises(TrueMultiAgentRuntimeError):
                    original_send_once(*captured[0])
                self.assertEqual(len(_LocalProviderHandler.requests), 1)
                self.journal.close()
                self.journal = None
                self.factory.close()
                self.factory = None
        _LocalProviderHandler.wire_case = None


if __name__ == "__main__":
    unittest.main()
