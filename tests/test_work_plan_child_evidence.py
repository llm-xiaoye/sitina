"""Phase evidence accepts owned completed work, never a parent approval."""
import copy
import unittest
from types import SimpleNamespace
from sitina.loop.coordinator import LoopBackend
from sitina.loop.model import EffectStatus,TaskConflict

class Memory:
    def __init__(self,documents):self.documents=documents;self.reads=[]
    def read(self,reference):
        self.reads.append(reference)
        return copy.deepcopy(self.documents[reference])

class WorkPlanChildEvidenceTests(unittest.TestCase):
    def setup_case(self):
        reference='cas:'+'a'*64
        report={'schema':'SITINA_LOOP_CHILD_RUNTIME_RESULT_V1','status':'SUCCEEDED',
                'delegation_id':'child-a','parent_binding':{'task_id':'parent-a'},'approves_parent':False}
        child={'status':'SETTLED','unknown_effect':False,'result_ref':reference}
        task=SimpleNamespace(task_id='parent-a',operations={},child_delegations={'child-a':child})
        memory=Memory({reference:report})
        backend=SimpleNamespace(context_memory=memory)
        plan={'steps':[{'id':'review','evidence_refs':[reference]}]}
        return backend,task,plan,report,child,reference
    def validate(self,backend,task,plan):
        return LoopBackend._validate_work_plan_evidence(backend,task,plan)
    def test_owned_settled_success_is_phase_evidence(self):
        b,t,p,*_=self.setup_case();self.validate(b,t,p)
        self.assertEqual(len(b.context_memory.reads),1)
    def test_unknown_effect_is_rejected_before_read(self):
        b,t,p,r,c,ref=self.setup_case();c['unknown_effect']=True
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
        self.assertEqual(b.context_memory.reads,[])
    def test_missing_unknown_state_is_not_assumed_safe(self):
        b,t,p,r,c,ref=self.setup_case();del c['unknown_effect']
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_retired_child_is_not_current_phase_evidence(self):
        b,t,p,r,c,ref=self.setup_case();c['status']='RETIRED'
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_blocked_report_is_rejected(self):
        b,t,p,r,c,ref=self.setup_case();r['status']='BLOCKED'
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_missing_success_status_is_rejected(self):
        b,t,p,r,c,ref=self.setup_case();del r['status']
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_cross_task_report_is_rejected(self):
        b,t,p,r,c,ref=self.setup_case();r['parent_binding']['task_id']='other-parent'
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_wrong_delegation_report_is_rejected(self):
        b,t,p,r,c,ref=self.setup_case();r['delegation_id']='other-child'
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_unknown_report_schema_is_rejected(self):
        b,t,p,r,c,ref=self.setup_case();r['schema']='unverified-report'
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_child_cannot_claim_parent_approval(self):
        b,t,p,r,c,ref=self.setup_case();r['approves_parent']=True
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_unowned_reference_is_rejected_without_cas_read(self):
        b,t,p,r,c,ref=self.setup_case();p['steps'][0]['evidence_refs']=['cas:'+'b'*64]
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
        self.assertEqual(b.context_memory.reads,[])
    def test_successful_provider_response_is_not_business_evidence(self):
        b,t,p,r,c,ref=self.setup_case();t.child_delegations={}
        t.operations={'provider-a':SimpleNamespace(operation_id='provider-a',effect_status=EffectStatus.SUCCEEDED,result_ref=ref)}
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_successful_business_operation_remains_eligible(self):
        b,t,p,r,c,ref=self.setup_case();t.child_delegations={}
        t.operations={'tool-a':SimpleNamespace(operation_id='tool-a',effect_status=EffectStatus.SUCCEEDED,result_ref=ref)}
        b.context_memory.documents[ref]={'result':{'tool':'sitina_read_file'}}
        self.validate(b,t,p)
    def test_plan_operation_cannot_prove_itself(self):
        b,t,p,r,c,ref=self.setup_case();t.child_delegations={}
        t.operations={'tool-a':SimpleNamespace(operation_id='tool-a',effect_status=EffectStatus.SUCCEEDED,result_ref=ref)}
        b.context_memory.documents[ref]={'result':{'tool':'sitina_plan'}}
        with self.assertRaises(TaskConflict):self.validate(b,t,p)
    def test_unreferenced_child_is_not_reloaded(self):
        b,t,p,r,c,ref=self.setup_case();p['steps'][0]['evidence_refs']=[]
        self.validate(b,t,p);self.assertEqual(b.context_memory.reads,[])

if __name__=='__main__':unittest.main()
