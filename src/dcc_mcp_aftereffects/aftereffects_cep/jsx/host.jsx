function dccMcpAfterEffects(raw) {
    var job = JSON.parse(raw); var project = app.project;
    if (job.action === "inspect_project") return JSON.stringify({project_name: project.file ? project.file.name : null, item_count: project.numItems, active_item: project.activeItem ? project.activeItem.name : null});
    if (job.action === "list_compositions") { var comps = []; for (var i = 1; i <= project.numItems; i++) { var item = project.item(i); if (item instanceof CompItem) comps.push({name: item.name, width: item.width, height: item.height, duration: item.duration}); } return JSON.stringify({compositions: comps, composition_count: comps.length}); }
    if (job.action === "save_project") { var path = job.params.path; if (!/^([A-Za-z]:[\\/]|\/)/.test(path) || !/\.aep$/i.test(path)) throw new Error("path must be absolute and end with .aep"); project.save(new File(path)); return JSON.stringify({path: path, saved: true}); }
    throw new Error("Unsupported action: " + job.action);
}
