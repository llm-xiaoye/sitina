class SitinaWorkPlan extends HTMLElement {
  constructor() { super(); this.signature = ""; }
  update(plan) {
    const signature = JSON.stringify(plan ?? null);
    if (signature === this.signature) return;
    this.signature = signature;
    this.replaceChildren();
    this.className = "work-plan";
    this.setAttribute("aria-label", plan ? "执行计划" : "操作记录");
    const make = (tag, cls, text) => {
      const node = document.createElement(tag); node.className = cls;
      if (text !== undefined) node.textContent = text;
      return node;
    };
    const heading = make("div", "work-plan-heading");
    heading.append(make("strong", "", plan ? "执行计划" : "操作记录"));
    this.append(heading);
    if (!plan) {
      this.append(make("p", "work-plan-empty", "下面显示本任务的实际操作。"));
      return;
    }
    const states = {pending:"未开始", in_progress:"进行中", completed:"已完成", blocked:"受阻"};
    const valid = plan.schema === "SITINA_WORK_PLAN_V1" && Array.isArray(plan.steps)
      && plan.steps.length > 0 && plan.steps.every(step => step && typeof step.id === "string"
        && typeof step.objective === "string" && typeof step.completion_condition === "string"
        && Array.isArray(step.depends_on) && Array.isArray(step.evidence_refs)
        && Object.hasOwn(states, step.status));
    if (!valid) {
      heading.append(make("span", "work-plan-count", "暂不可读"));
      this.append(make("p", "work-plan-empty", "计划记录暂时无法读取；可以继续查看下面的实际操作。"));
      return;
    }
    heading.append(make("span", "work-plan-count",
      "已完成 " + plan.steps.filter(step => step.status === "completed").length + " / " + plan.steps.length));
    const list = make("ol", "work-plan-steps");
    plan.steps.forEach((step, index) => {
      const row = make("li", "work-plan-step " + step.status);
      row.dataset.stepId = step.id;
      if (step.status === "in_progress") row.setAttribute("aria-current", "step");
      const mark = make("span", "work-plan-mark", step.status === "completed" ? "✓" : String(index + 1));
      mark.setAttribute("aria-hidden", "true");
      const body = make("div", "work-plan-body");
      body.append(make("strong", "", step.objective));
      const details = make("details", "work-plan-condition");
      details.append(make("summary", "", "完成条件"),make("p", "", step.completion_condition));
      body.append(details);
      row.append(mark, body, make("span", "work-plan-state", states[step.status]));
      list.append(row);
    });
    this.append(list);
  }
}
customElements.define("sitina-work-plan", SitinaWorkPlan);

