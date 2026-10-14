/*
 * Ordenação de tabelas no navegador.
 * Uso: <table data-sortable id="...">, <th data-sort-type="num|text"> e, nas células,
 * data-sort="valor" (se ausente, usa o texto da célula). Clique no título alterna
 * crescente/decrescente. Valores vazios ficam sempre no fim. A última escolha é
 * lembrada neste navegador.
 */
(() => {
  const collator = new Intl.Collator("pt-BR", { sensitivity: "base", numeric: true });
  const load = (key) => { try { return JSON.parse(localStorage.getItem(key)); } catch { return null; } };
  const save = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* sem armazenamento */ } };

  document.querySelectorAll("table[data-sortable]").forEach((table) => {
    const tbody = table.tBodies[0];
    const headers = [...table.tHead.rows[0].cells];
    const storeKey = table.id ? `ordenacao:${table.id}` : null;
    [...tbody.rows].forEach((row, i) => { row.dataset.originalIndex = i; });

    const valueOf = (row, col) => {
      const cell = row.cells[col];
      return (cell.dataset.sort ?? cell.textContent).trim();
    };

    const sortBy = (col, dir) => {
      const type = headers[col].dataset.sortType || "text";
      const rows = [...tbody.rows];
      rows.sort((a, b) => {
        const va = valueOf(a, col), vb = valueOf(b, col);
        if (!va || !vb) {  // vazios sempre no fim
          if (va === vb) return a.dataset.originalIndex - b.dataset.originalIndex;
          return va ? -1 : 1;
        }
        const cmp = type === "num" ? Number(va) - Number(vb) : collator.compare(va, vb);
        return (dir === "asc" ? cmp : -cmp) || a.dataset.originalIndex - b.dataset.originalIndex;
      });
      tbody.append(...rows);
      headers.forEach((th, i) => {
        if (th.dataset.sortType === undefined) return;
        th.setAttribute("aria-sort", i === col ? (dir === "asc" ? "ascending" : "descending") : "none");
      });
      if (storeKey) save(storeKey, { col, dir });
    };

    headers.forEach((th, col) => {
      if (th.dataset.sortType === undefined) return;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "sort-btn";
      btn.innerHTML = `<span></span><i aria-hidden="true"></i>`;
      btn.firstChild.textContent = th.textContent;
      btn.title = "Clique para ordenar (crescente / decrescente)";
      th.textContent = "";
      th.append(btn);
      if (!th.hasAttribute("aria-sort")) th.setAttribute("aria-sort", "none");
      btn.addEventListener("click", () => {
        sortBy(col, th.getAttribute("aria-sort") === "ascending" ? "desc" : "asc");
      });
    });

    const saved = storeKey && load(storeKey);
    if (saved && headers[saved.col] && headers[saved.col].dataset.sortType !== undefined) {
      sortBy(saved.col, saved.dir === "desc" ? "desc" : "asc");
    }
  });
})();
