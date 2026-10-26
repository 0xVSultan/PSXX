// The page: reads the files the user picks (they never leave the machine), calls X.verify, shows the report.
(function () {
  const $ = (id) => document.getElementById(id);
  const files = {};
  const readFile = (f) => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(new Uint8Array(r.result)); r.onerror = () => rej(r.error); r.readAsArrayBuffer(f); });
  const hold = (id, key) => $(id).addEventListener("change", async (e) => {
    const f = e.target.files[0];
    files[key] = f ? await readFile(f) : null;
    $(id + "-n").textContent = f ? `${f.name}, ${f.size} bytes` : "";
  });
  hold("f-a", "boot");
  $("f-b").addEventListener("change", async (e) => {
    files.others = await Promise.all(Array.from(e.target.files, async (f) => ({ name: f.name, data: await readFile(f) })));
    $("f-b-n").textContent = files.others.map((o) => `${o.name}, ${o.data.length} bytes`).join("; ");
  });
  for (const [id, target] of [["f-ev", "event"], ["f-man", "manifest"]]) {
    $(id).addEventListener("change", async (e) => {
      const f = e.target.files[0];
      if (f) $(target).value = new TextDecoder().decode(await readFile(f));
    });
  }
  $("go").addEventListener("click", () => {
    const out = $("out"), sum = $("sum");
    out.textContent = "";
    sum.textContent = "Checking…";
    sum.className = "sum";
    setTimeout(() => {
      let r;
      try {
        r = X.verify({ trust: $("trust").value, boot: files.boot, others: files.others, event: $("event").value, manifest: $("manifest").value, imageSize: parseInt($("size").value, 10) || 0 });
      } catch (e) { sum.textContent = "The check stopped: " + e.message; sum.className = "sum fail"; return; }
      const nfail = r.results.filter((x) => x.status === "fail").length;
      sum.className = "sum " + (nfail ? "fail" : r.ok ? "ok" : "warn");
      const nwarn = r.results.filter((x) => x.status === "warn").length;
      sum.textContent = nfail ? `${nfail} check(s) FAILED: do not trust these files.` : r.ok ? "Every check that could run passed" + (nwarn ? `; ${nwarn} point(s) are not covered (marked !).` : ".") : "Nothing could be checked: give some files.";
      for (const x of r.results) {
        const li = document.createElement("li");
        li.className = x.status;
        const b = document.createElement("b");
        b.textContent = { ok: "✓ ", fail: "✗ ", warn: "! ", skip: "– ", info: "· " }[x.status] + x.title;
        const d = document.createElement("span");
        d.textContent = x.detail;
        li.append(b, d);
        out.append(li);
      }
    }, 20);
  });
})();
