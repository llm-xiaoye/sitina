"""Explicit cancellation of a missing pure-model response, without replay.

The original operation remains UNKNOWN.  This receipt discharges only the
need to obtain that response before cancellation; it does not settle billing,
authorize a successor model request, or reconcile any business write.
"""
from collections.abc import Mapping
import re

from .model import ControlIntent, EffectStatus, InputKind, OperationMode, TaskConflict


IDENTITY_KEYS = (
    'provider_identity', 'environment_ref', 'capability_snapshot_id',
    'software_identity', 'config_identity',
)
REQUEST_KEYS = {
    'expected_task_revision', 'expected_run_instance_id', 'expected_execution_epoch',
    'expected_received_input_seq', 'expected_handled_input_seq', 'descriptor_hash',
    'from_software_identity', 'to_software_identity', 'operation_id',
    'result_ref', 'result_hash', 'confirm_cancel', 'accept_unknown_usage',
    'abandon_missing_response',
}


def validate_cancel_reconciliation(task, request, *, request_id, host_context, read, events):
    if not isinstance(request, Mapping) or set(request) not in (
        REQUEST_KEYS, REQUEST_KEYS | {'abandon_inspection_result'},
    ):
        raise TaskConflict('cancel reconciliation fields are invalid')
    if 'abandon_inspection_result' in request and request['abandon_inspection_result'] is not True:
        raise TaskConflict('explicit acceptance of the incomplete inspection is required')
    if not isinstance(request_id, str) or not request_id or len(request_id) > 160:
        raise TaskConflict('cancel reconciliation needs a bounded request identity')
    if (task.is_terminal or task.control_intent is not ControlIntent.CANCEL
            or task.active_operations or task.cancel_reconciliation is not None):
        raise TaskConflict('cancel reconciliation requires a stopped, cancelled task')
    if request['confirm_cancel'] is not True:
        raise TaskConflict('explicit cancellation confirmation is required')
    for key in ('accept_unknown_usage', 'abandon_missing_response'):
        if type(request[key]) is not bool:
            raise TaskConflict('cancel confirmation flags must be booleans')
    for key in ('task_revision', 'execution_epoch', 'received_input_seq', 'handled_input_seq'):
        if type(request['expected_' + key]) is not int or request['expected_' + key] != getattr(task, key):
            raise TaskConflict('cancel reconciliation frontier is stale')
    if request['expected_run_instance_id'] != task.run_instance_id:
        raise TaskConflict('cancel reconciliation owner changed')
    if (not task.descriptor_ref or not task.descriptor_hash
            or request['descriptor_hash'] != task.descriptor_hash):
        raise TaskConflict('cancel reconciliation descriptor differs')
    if any(record.sequence > task.handled_input_seq and record.kind not in {InputKind.PAUSE, InputKind.CANCEL}
           for record in task.inputs):
        raise TaskConflict('unhandled business input must not be discarded')
    descriptor = read(task.descriptor_ref, expected_hash=task.descriptor_hash)
    if not isinstance(host_context, Mapping) or set(host_context) != set(IDENTITY_KEYS):
        raise TaskConflict('cancel reconciliation requires the exact Host identity')
    for key in IDENTITY_KEYS:
        if not isinstance(host_context[key], str) or not host_context[key]:
            raise TaskConflict('cancel Host identity is incomplete')
        if key != 'software_identity' and descriptor.get(key) != host_context[key]:
            raise TaskConflict('cancel must not change provider, environment, configuration or capabilities')
    for key in ('from_software_identity', 'to_software_identity'):
        if not isinstance(request[key], str) or re.fullmatch(r'source:[0-9a-f]{64}', request[key]) is None:
            raise TaskConflict('cancel needs exact source identities')
    if (request['from_software_identity'] != descriptor.get('software_identity')
            or request['to_software_identity'] != host_context['software_identity']):
        raise TaskConflict('cancel source pair differs')

    if request.get('abandon_inspection_result') is True:
        from .inspection_cancel import validate_inspection_cancel
        return validate_inspection_cancel(
            task, request, request_id=request_id, host_context=host_context, read=read, events=events,
        )

    pending = tuple(task.unresolved_effects)
    operation_id = request['operation_id']
    if not pending:
        if (any(request[key] is not None for key in ('operation_id', 'result_ref', 'result_hash'))
                or request['accept_unknown_usage'] or request['abandon_missing_response']):
            raise TaskConflict('a settled task cannot invent a missing model response')
    else:
        if (len(pending) != 1 or pending[0].operation_id != operation_id
                or request['accept_unknown_usage'] is not True
                or request['abandon_missing_response'] is not True):
            raise TaskConflict('only one explicitly accepted pure-model UNKNOWN can be abandoned')
        operation = pending[0]
        if (operation.mode is not OperationMode.READ or operation.effect_status is not EffectStatus.UNKNOWN
                or not operation.unknown_effect or operation.recovery_decision != 'NO_RETRY'
                or operation.agent_role not in {'main', 'reviewer', 'goal_completion'}
                or operation.execution_owner is not None or operation.resources
                or ':provider-turn:' not in operation.logical_operation_id
                or not operation.operation_id.startswith('provider-')
                or operation.result_ref != request['result_ref'] or not operation.intent_ref
                or operation.bound_goal_version != task.goal_version
                or operation.bound_acceptance_version != task.acceptance_version
                or operation.bound_input_seq > task.handled_input_seq):
            raise TaskConflict('this UNKNOWN is not a pure-model cancellation candidate')
        if any(record.sequence > operation.bound_input_seq and record.kind not in {InputKind.PAUSE, InputKind.CANCEL}
               for record in task.inputs):
            raise TaskConflict('the original model request was superseded by business input')
        history = [event for event in events if event.position <= task.stream_frontier]
        results = [event for event in history if event.event_type == 'loop.operation-result-recorded'
                   and event.payload.get('operation_id') == operation_id]
        if (len(results) != 1 or results[0].payload.get('result_ref') != request['result_ref']
                or results[0].payload.get('result_hash') != request['result_hash']
                or not isinstance(request['result_hash'], str)
                or re.fullmatch(r'[0-9a-f]{64}', request['result_hash']) is None):
            raise TaskConflict('cancel requires the unique committed original result')
        intent = read(operation.intent_ref)
        if (intent.get('schema') != 'SITINA_LOOP_OPERATION_INTENT_V1'
                or intent.get('task_id') != task.task_id or intent.get('operation_id') != operation_id
                or intent.get('logical_operation_id') != operation.logical_operation_id
                or intent.get('agent_role') != operation.agent_role or intent.get('mode') != 'READ'
                or intent.get('resources') != [] or intent.get('execution_owner') is not None
                or intent.get('write_authority_acquired') is not False
                or intent.get('expected_goal_version') != operation.bound_goal_version
                or intent.get('expected_acceptance_version') != operation.bound_acceptance_version
                or intent.get('expected_handled_input_seq') != operation.bound_input_seq):
            raise TaskConflict('cancel request does not match the original read-only intent')
        document = read(operation.result_ref, expected_hash=request['result_hash'])
        body = document.get('result')
        failure = body.get('provider_failure') if isinstance(body, Mapping) else None
        if (document.get('schema') != 'SITINA_LOOP_OPERATION_RESULT_V1'
                or document.get('task_id') != task.task_id or document.get('operation_id') != operation_id
                or document.get('effect_status') != 'UNKNOWN'
                or document.get('bound_goal_version') != operation.bound_goal_version
                or document.get('bound_acceptance_version') != operation.bound_acceptance_version
                or document.get('bound_input_seq') != operation.bound_input_seq
                or not isinstance(body, Mapping) or body.get('work_purpose') != operation.agent_role
                or body.get('business_effect_dispatched') is not False
                or body.get('provider_response_discarded') is not True
                or body.get('recovery_decision') != 'NO_RETRY' or body.get('effect_requires_probe') is not True
                or body.get('tool_calls') not in (None, [])
                or body.get('private_rejected_tool_response') is not None
                or not isinstance(failure, Mapping)
                or failure.get('schema') != 'SITINA_LOOP_PROVIDER_FAILURE_V1'
                or failure.get('failure_class') != 'unknown_provider_failure'
                or failure.get('business_effect_dispatched') is not False
                or failure.get('usage_unsettled') is not True
                or any(type(failure.get(key)) is not int or failure[key] != 0
                       for key in ('retry_count', 'fallback_count'))):
            raise TaskConflict('original receipt does not exclude dispatched business tools')
        uncertain = (
            body.get('effect_dispatched') is None and failure.get('effect_dispatched') is None
            and failure.get('physical_send_status') == 'unknown_after_request_start'
            and failure.get('physical_send_count_status') == 'lower_bound_with_uncertain_attempts'
            and all(type(failure.get(key)) is int and failure[key] == value for key, value in
                    (('physical_send_count', 0), ('physical_send_count_lower_bound', 0),
                     ('uncertain_physical_send_attempt_count', 1)))
        )
        confirmed = (
            body.get('effect_dispatched') is True and failure.get('effect_dispatched') is True
            and failure.get('physical_send_status') == 'request_sent_no_response'
            and failure.get('physical_send_count_status') == 'exact'
            and all(type(failure.get(key)) is int and failure[key] == value for key, value in
                    (('physical_send_count', 1), ('physical_send_count_lower_bound', 1),
                     ('uncertain_physical_send_attempt_count', 0)))
        )
        if not (uncertain or confirmed):
            raise TaskConflict('model send evidence has an unsupported shape')
    return {
        'schema': 'SITINA_LOOP_CANCEL_RECONCILIATION_V1',
        'authorization_source': 'native_control_cancel', 'request_id': request_id,
        'task_id': task.task_id, 'descriptor_ref': task.descriptor_ref,
        'descriptor_hash': task.descriptor_hash, 'request': dict(request),
        'host_descriptor_context': dict(host_context),
        'decision': 'CANCEL_WITHOUT_REPLAY', 'successor': 'CANCEL_ONLY',
        'abandoned_operation_id': operation_id,
        'original_effect_status': 'UNKNOWN' if operation_id is not None else None,
        'usage_unsettled': operation_id is not None,
        'business_dispatch_allowed': False,
    }
