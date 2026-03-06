(() => {
    const ENDPOINTS = {
      clients: "/api/clients/",
      sites: "/api/sites/",
      assets: "/api/assets/",
    };
  
    const state = {
      loaded: false,
      loading: null,
      data: { clients: [], sites: [], assets: [] },
    };
  
    function norm(v) {
      return String(v ?? "").toLowerCase().trim();
    }
  
    function escapeHtml(s) {
      return String(s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }
  
    function debounce(fn, delayMs) {
      let t = null;
      return (...args) => {
        if (t) clearTimeout(t);
        t = setTimeout(() => fn(...args), delayMs);
      };
    }
  
    async function loadAllOnce() {
      if (state.loaded) return state.data;
      if (state.loading) return state.loading;
  
      state.loading = (async () => {
        const [clients, sites, assets] = await Promise.all([
          fetch(ENDPOINTS.clients).then((r) => r.json()),
          fetch(ENDPOINTS.sites).then((r) => r.json()),
          fetch(ENDPOINTS.assets).then((r) => r.json()),
        ]);
        state.data = { clients, sites, assets };
        state.loaded = true;
        return state.data;
      })().finally(() => {
        state.loading = null;
      });
  
      return state.loading;
    }
  
    function buildItem({ href, title, subtitle, badge, badgeClass }) {
      const badgeHtml = badge
        ? `<span class="badge ${badgeClass ?? "bg-secondary"} me-2">${escapeHtml(badge)}</span>`
        : "";
      const subtitleHtml = subtitle
        ? `<div class="small am-search-muted">${escapeHtml(subtitle)}</div>`
        : "";
  
      return `
        <a class="dropdown-item py-2" href="${escapeHtml(href)}">
          <div class="d-flex align-items-start">
            <div class="flex-grow-1">
              <div class="fw-semibold">${badgeHtml}${escapeHtml(title)}</div>
              ${subtitleHtml}
            </div>
          </div>
        </a>
      `;
    }
  
    function renderMenu(menuEl, query, data) {
      const q = norm(query);
      if (!q) {
        menuEl.innerHTML = `
          <div class="px-3 py-2 small am-search-muted">
            Tape pour chercher un client, un site ou un asset…
          </div>
        `;
        return;
      }
  
      const MAX_PER_SECTION = 6;
  
      const clients = data.clients
        .filter((c) => norm(c.nom).includes(q))
        .slice(0, MAX_PER_SECTION)
        .map((c) =>
          buildItem({
            href: `/ui/clients?q=${encodeURIComponent(query)}`,
            title: c.nom ?? "Client",
            subtitle: c.contact_email || c.contact_nom || c.adresse || null,
            badge: "Client",
            badgeClass: "bg-primary",
          })
        );
  
      const sites = data.sites
        .filter((s) => norm(s.nom).includes(q) || norm(s.client_nom).includes(q))
        .slice(0, MAX_PER_SECTION)
        .map((s) =>
          buildItem({
            href: `/ui/sites?q=${encodeURIComponent(query)}`,
            title: s.nom ?? "Site",
            subtitle: [s.client_nom, s.adresse].filter(Boolean).join(" • ") || null,
            badge: "Site",
            badgeClass: "bg-info text-dark",
          })
        );
  
      const assets = data.assets
        .filter((a) => {
          const hay = [
            a.nom_interne,
            a.hostname,
            a.adresse_ip,
            a.type_equipement,
            a.client_nom,
            a.site_nom,
          ]
            .map(norm)
            .join(" ");
          return hay.includes(q);
        })
        .slice(0, MAX_PER_SECTION)
        .map((a) =>
          buildItem({
            href: `/ui/assets?q=${encodeURIComponent(query)}`,
            title: a.nom_interne ?? "Asset",
            subtitle:
              [
                a.client_nom && `Client: ${a.client_nom}`,
                a.site_nom && `Site: ${a.site_nom}`,
                a.adresse_ip && `IP: ${a.adresse_ip}`,
                a.hostname && `Host: ${a.hostname}`,
              ]
                .filter(Boolean)
                .join(" • ") || null,
            badge: "Asset",
            badgeClass: "bg-secondary",
          })
        );
  
      const sections = [
        { label: "Clients", items: clients },
        { label: "Sites", items: sites },
        { label: "Assets", items: assets },
      ].filter((s) => s.items.length);
  
      if (!sections.length) {
        menuEl.innerHTML = `
          <div class="px-3 py-2 small am-search-muted">
            Aucun résultat pour “${escapeHtml(query)}”.
          </div>
        `;
        return;
      }
  
      menuEl.innerHTML = sections
        .map(
          (s) => `
            <div class="dropdown-header text-uppercase small">${escapeHtml(s.label)}</div>
            ${s.items.join("")}
            <div class="dropdown-divider my-1"></div>
          `
        )
        .join("")
        .replace(/<div class="dropdown-divider my-1"><\/div>\s*$/m, "");
    }
  
    function initOne(inputEl) {
      const root = inputEl.closest("[data-am-search-root]") || inputEl.parentElement;
      const menuEl = root?.querySelector("[data-am-search-menu]");
      if (!menuEl) return;
  
      // Pré-remplir via ?q=
      const urlQ = new URLSearchParams(window.location.search).get("q");
      if (urlQ && !inputEl.value) inputEl.value = urlQ;
  
      const open = () => menuEl.classList.add("show");
      const close = () => menuEl.classList.remove("show");
  
      const doSearch = debounce(async () => {
        open();
        menuEl.innerHTML = `<div class="px-3 py-2 small am-search-muted">Recherche…</div>`;
        try {
          const data = await loadAllOnce();
          renderMenu(menuEl, inputEl.value, data);
        } catch (e) {
          menuEl.innerHTML = `<div class="px-3 py-2 small text-danger">Erreur chargement recherche</div>`;
        }
      }, 180);
  
      inputEl.addEventListener("input", () => doSearch());
      inputEl.addEventListener("focus", () => doSearch());
  
      document.addEventListener("click", (e) => {
        if (!root.contains(e.target)) close();
      });
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") close();
      });
  
      // Si on a ?q=, lancer une recherche immédiatement pour montrer les résultats.
      if (urlQ) doSearch();
    }
  
    document.addEventListener("DOMContentLoaded", () => {
      document.querySelectorAll("[data-am-search-input]").forEach(initOne);
    });
  })();
  
  