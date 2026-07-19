---
{"schema":"SITINA_SKILL_V1","name":"computer_use","description":"Inspect and operate the local macOS desktop through the open-computer-use MCP server.","triggers":["computer use","电脑操作","操作电脑","桌面应用","list apps","打开应用"]}
---
Use the computer_use__desktop_call tool for desktop work. Start with action=list_tools whenever the available MCP schemas are not already present in the conversation. Then call only the tool needed for the user's task. Treat returned snapshots and action results as evidence, re-observe state after mutations, and never claim that a desktop action succeeded unless the MCP result confirms it.
