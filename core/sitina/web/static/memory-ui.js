function setupMemoryUI({api, currentSession}) {
  const get = id => document.getElementById(id);
  const dialog=get("memory-dialog"), list=get("memory-list"), notice=get("memory-notice");
  let editing=null, reading=false, saving=false, lastSession=null;
  const node=(tag,cls,text)=>{const e=document.createElement(tag);e.className=cls;if(text!==undefined)e.textContent=text;return e;};
  function edit(item) {
    editing=item?.id || null;
    get("memory-form-title").textContent=editing?"修改记忆":"添加记忆";
    get("memory-kind").value=item?.kind || "preference";get("memory-kind").disabled=!!editing;
    get("memory-content").value=item?.content || "";get("memory-edit-cancel").hidden=!editing;
    if (item) get("memory-content").focus();
  }
  async function act(body) {
    if (saving) return;
    saving=true;notice.textContent="正在保存…";
    try {await api("/api/memory",{method:"POST",body:{...body,session_id:currentSession()}});notice.textContent="已保存。下次发送消息时使用最新确认的记忆。";await refresh();}
    catch(error){notice.textContent=error.message;}
    finally{saving=false;}
  }
  function row(item) {
    const card=node("article","memory-item");
    const heading=node("div","memory-item-heading");
    heading.append(node("strong","",item.kind==="preference"?"用户偏好":"项目事实 · "+item.project),
      node("span",item.status==="candidate"?"memory-pending":"memory-active",item.status==="candidate"?"待确认，不生效":"已生效"));
    const details=node("details","memory-source");details.append(node("summary","","来源"));
    details.append(node("p","",item.source?.type==="user_edit"?"你在记忆页面保存":item.source?.type==="user_request"?"来自明确的记住指令":"自动提炼的候选"));
    if(item.source?.quote)details.append(node("blockquote","",item.source.quote));
    const actions=node("div","memory-actions");
    if(item.status==="candidate"){
      const approve=node("button","primary-button","确认并生效");approve.type="button";
      approve.onclick=()=>act({action:"approve",id:item.id});actions.append(approve);
    }
    const change=node("button","secondary-button","修改");change.type="button";change.onclick=()=>edit(item);
    const remove=node("button","secondary-button","删除");remove.type="button";
    remove.onclick=()=>{
      if(remove.dataset.confirm==="yes"){act({action:"delete",id:item.id});if(editing===item.id)edit(null);}
      else {remove.dataset.confirm="yes";remove.textContent="确认永久删除";remove.classList.add("danger-text");}
    };
    actions.append(change,remove);card.append(heading,node("p","memory-content",item.content),details,actions);return card;
  }
  async function refresh() {
    if(reading)return;reading=true;
    const sid=currentSession();
    try {
      const data=await api("/api/memory"+(sid?"?session_id="+encodeURIComponent(sid):""));
      if(sid!==currentSession())return;
      const candidates=data.items.filter(item=>item.status==="candidate").length;
      get("open-memory").textContent="记忆"+(candidates?" · "+candidates+" 待确认":"");
      if(dialog.open){
        if(document.activeElement!==get("memory-project"))get("memory-project").value=data.project;
        list.replaceChildren(...data.items.map(row));
        if(!data.items.length)list.append(node("p","muted","还没有记忆。可以在下方添加，也可以在对话中明确说“记住……”。"));
      }
      lastSession=sid;
    }catch(error){if(dialog.open)notice.textContent=error.message;}finally{reading=false;}
  }
  get("open-memory").onclick=()=>{notice.textContent="";edit(null);dialog.showModal();refresh();};
  get("close-memory").onclick=()=>dialog.close();
  get("memory-edit-cancel").onclick=()=>edit(null);
  get("memory-project-form").onsubmit=event=>{event.preventDefault();if(!currentSession()){notice.textContent="请先选择或新建会话。";return;}edit(null);act({action:"set_project",project:get("memory-project").value});};
  get("memory-form").onsubmit=async event=>{
    event.preventDefault();
    const content=get("memory-content").value.trim();if(!content)return;
    await act({action:"save",id:editing,kind:get("memory-kind").value,content});
    if(!notice.textContent.includes("无效") && notice.textContent.startsWith("已保存"))edit(null);
  };
  setInterval(()=>{if(!saving&&(dialog.open||currentSession()!==lastSession))refresh();},3000);
  // Candidate changes may arrive while a task runs, even without navigation.
  setInterval(()=>{if(!saving)refresh();},10000);
  refresh();
}

