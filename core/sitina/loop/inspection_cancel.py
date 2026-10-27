"""Cancel-only disposition of an authenticated built-in Skill inspection.

This is not a general READ-operation exemption. The original result remains
UNKNOWN; an explicit disposition waives only the missing inspection result.
Installation and other tool effects cannot use this path.
"""
from collections.abc import Mapping
import re
from urllib.parse import urlsplit

from .model import EffectStatus, InputKind, OperationMode, TaskConflict


def validate_inspection_cancel(task, request, *, request_id, host_context, read, events):
    """Called only after the common cancellation frontier/Host checks."""
    pending = tuple(task.unresolved_effects)
    operation_id = request['operation_id']
    if (len(pending) != 1 or pending[0].operation_id != operation_id
            or request['accept_unknown_usage'] is not False
            or request['abandon_missing_response'] is not False):
        raise TaskConflict('inspection cancellation cannot abandon model usage or another operation')
    operation = pending[0]
    if (operation.mode is not OperationMode.READ or operation.effect_status is not EffectStatus.UNKNOWN
            or not operation.unknown_effect or operation.agent_role != 'main'
            or operation.execution_owner is not None or operation.resources
            or not operation_id.startswith('task-skill-management-')
            or operation.result_ref != request['result_ref'] or not operation.intent_ref
            or operation.bound_goal_version != task.goal_version
            or operation.bound_acceptance_version != task.acceptance_version
            or operation.bound_input_seq > task.handled_input_seq):
        raise TaskConflict('this UNKNOWN is not a built-in read-only Skill inspection')
    if any(record.sequence > operation.bound_input_seq and record.kind not in {InputKind.PAUSE, InputKind.CANCEL}
           for record in task.inputs):
        raise TaskConflict('inspection was superseded by business input')
    logical = operation.logical_operation_id.split(':sitina_manage_skills:')
    if len(logical) != 2 or not logical[0].startswith('agent-run-') or not logical[1]:
        raise TaskConflict('inspection requires its original run and model call identity')
    run_id, call_id = logical
    history = [event for event in events if event.position <= task.stream_frontier]
    intents = [event for event in history if event.event_type == 'loop.operation-intent-recorded'
               and event.payload.get('operation_id') == operation_id]
    results = [event for event in history if event.event_type == 'loop.operation-result-recorded'
               and event.payload.get('operation_id') == operation_id]
    dispatches = [event for event in history if event.event_type == 'loop.operation-dispatch-started'
                  and event.payload.get('operation_id') == operation_id]
    if (len(intents) != 1 or len(results) != 1 or len(dispatches) != 1
            or not intents[0].position < dispatches[0].position < results[0].position
            or intents[0].payload.get('intent_ref') != operation.intent_ref
            or dispatches[0].payload.get('logical_operation_id') != operation.logical_operation_id
            or results[0].payload.get('result_ref') != request['result_ref']
            or results[0].payload.get('result_hash') != request['result_hash']
            or not isinstance(request['result_hash'], str)
            or re.fullmatch(r'[0-9a-f]{64}', request['result_hash']) is None):
        raise TaskConflict('inspection lacks a unique authenticated dispatch and result')
    intent = read(operation.intent_ref, expected_hash=intents[0].payload['intent_hash'])
    if (intent.get('schema') != 'SITINA_LOOP_OPERATION_INTENT_V1'
            or intent.get('task_id') != task.task_id or intent.get('operation_id') != operation_id
            or intent.get('logical_operation_id') != operation.logical_operation_id
            or intent.get('agent_role') != 'main' or intent.get('mode') != 'READ'
            or intent.get('resources') != [] or intent.get('execution_owner') is not None
            or intent.get('write_authority_acquired') is not False
            or intent.get('expected_goal_version') != operation.bound_goal_version
            or intent.get('expected_acceptance_version') != operation.bound_acceptance_version
            or intent.get('expected_handled_input_seq') != operation.bound_input_seq):
        raise TaskConflict('original inspection intent does not exclude installation authority')
    document = read(operation.result_ref, expected_hash=request['result_hash'])
    body = document.get('result')
    if (document.get('schema') != 'SITINA_LOOP_OPERATION_RESULT_V1'
            or document.get('task_id') != task.task_id or document.get('operation_id') != operation_id
            or document.get('effect_status') != 'UNKNOWN'
            or document.get('bound_goal_version') != operation.bound_goal_version
            or document.get('bound_acceptance_version') != operation.bound_acceptance_version
            or document.get('bound_input_seq') != operation.bound_input_seq
            or not isinstance(body, Mapping)
            or set(body) != {'effect_requires_probe', 'exception_type', 'exception_hash'}
            or body['effect_requires_probe'] is not True
            or body['exception_type'] != 'ExtensionAuthorityError'
            or not isinstance(body['exception_hash'], str)
            or re.fullmatch(r'sha256:[0-9a-f]{64}', body['exception_hash']) is None):
        raise TaskConflict('inspection result is not a supported original failure receipt')
    calls = []
    for event in history:
        if event.event_type != 'loop.operation-result-recorded' or event.position >= intents[0].position:
            continue
        provider = task.operations.get(event.payload.get('operation_id'))
        if (provider is None or not provider.operation_id.startswith('provider-')
                or not provider.logical_operation_id.startswith(run_id + ':provider-turn:')
                or provider.mode is not OperationMode.READ or provider.agent_role != 'main'
                or provider.result_ref != event.payload.get('result_ref')
                or event.payload.get('effect_status') != 'SUCCEEDED'):
            continue
        response = read(provider.result_ref, expected_hash=event.payload['result_hash'])
        value = response.get('result')
        if (response.get('task_id') != task.task_id or response.get('operation_id') != provider.operation_id
                or response.get('effect_status') != 'SUCCEEDED'
                or not isinstance(value, Mapping) or value.get('work_purpose') != 'main'
                or value.get('goal_version') != operation.bound_goal_version
                or value.get('acceptance_version') != operation.bound_acceptance_version
                or value.get('handled_input_seq') != operation.bound_input_seq
                or not isinstance(value.get('tool_calls'), list)):
            raise TaskConflict('original inspection model response has an invalid binding')
        for call in value['tool_calls']:
            if isinstance(call, Mapping) and call.get('id') == call_id:
                calls.append((call, event.payload))
    if len(calls) != 1:
        raise TaskConflict('original inspection tool call is missing or ambiguous')
    call, provider_receipt = calls[0]
    arguments = call.get('arguments')
    if (call.get('name') != 'sitina_manage_skills' or not isinstance(arguments, Mapping)
            or set(arguments) != {'action', 'source'} or arguments['action'] != 'inspect'
            or not isinstance(arguments['source'], str) or not 0 < len(arguments['source']) <= 4096):
        raise TaskConflict('installation, status or another tool cannot use inspection cancellation')
    source = urlsplit(arguments['source'])
    if source.scheme != 'https' or not source.hostname or source.username is not None or source.password is not None:
        raise TaskConflict('inspection source is not an anonymous public HTTPS source')
    if any(item.mode is OperationMode.WRITE and ':sitina_manage_skills:' in item.logical_operation_id
           for item in task.operations.values()):
        raise TaskConflict('task also contains a Skill installation; reconcile it separately')
    return {
        'schema': 'SITINA_LOOP_CANCEL_RECONCILIATION_V1',
        'authorization_source': 'native_control_cancel', 'request_id': request_id,
        'task_id': task.task_id, 'descriptor_ref': task.descriptor_ref,
        'descriptor_hash': task.descriptor_hash, 'request': dict(request),
        'host_descriptor_context': dict(host_context),
        'decision': 'CANCEL_WITHOUT_REPLAY', 'successor': 'CANCEL_ONLY',
        'abandoned_operation_id': operation_id, 'original_effect_status': 'UNKNOWN',
        'usage_unsettled': False, 'business_dispatch_allowed': False,
        'abandoned_result_kind': 'BUILTIN_SKILL_SOURCE_INSPECTION',
        'inspection_completion_unsettled': True, 'temporary_download_state': 'UNKNOWN',
        'installation_dispatch_excluded': True,
        'original_tool_call': {'id': call_id, 'run_id': run_id, 'source': arguments['source'],
                               'provider_result_ref': provider_receipt['result_ref'],
                               'provider_result_hash': provider_receipt['result_hash']},
    }
