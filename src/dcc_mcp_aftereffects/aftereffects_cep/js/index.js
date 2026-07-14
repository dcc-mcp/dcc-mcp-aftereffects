var baseUrl = "http://127.0.0.1:47394";
var token = "dev-token"; // Set the same value as DCC_MCP_AFTEREFFECTS_BRIDGE_TOKEN before production use.
function request(method, path, body, done) { var xhr = new XMLHttpRequest(); xhr.open(method, baseUrl + path, true); xhr.setRequestHeader("X-DCC-MCP-Token", token); xhr.setRequestHeader("Content-Type", "application/json"); xhr.onload = function () { done(xhr.responseText); }; xhr.send(body ? JSON.stringify(body) : null); }
function poll() { request("GET", "/next", null, function (raw) { var job = JSON.parse(raw); if (!job.id) return setTimeout(poll, 50); window.__adobe_cep__.evalScript("dccMcpAfterEffects(" + JSON.stringify(JSON.stringify(job)) + ")", function (response) { var result; var error = null; try { result = JSON.parse(response); } catch (e) { error = response || String(e); } request("POST", "/result", {id: job.id, result: result, error: error}, function () { setTimeout(poll, 0); }); }); }); }
poll();
