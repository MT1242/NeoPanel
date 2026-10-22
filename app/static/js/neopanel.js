(() => {
    const root = document.documentElement;
    const themeKey = "neopanel-theme";
    const sidebarKey = "neopanel-sidebar";

    const setTheme = (next) => {
        root.dataset.theme = next;
        try { localStorage.setItem(themeKey, next); } catch (_) { /* ignore */ }
    };

    document.querySelector("[data-theme-toggle]")?.addEventListener("click", () => {
        setTheme(root.dataset.theme === "dark" ? "light" : "dark");
    });

    document.querySelector("[data-sidebar-toggle]")?.addEventListener("click", () => {
        root.classList.toggle("sidebar-collapsed");
        try {
            localStorage.setItem(sidebarKey, root.classList.contains("sidebar-collapsed") ? "collapsed" : "open");
        } catch (_) { /* ignore */ }
    });

    document.querySelectorAll("[data-nav-toggle]").forEach((button) => {
        button.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            const tree = button.closest("[data-nav-tree]");
            if (!tree) return;
            const open = tree.classList.toggle("is-open");
            button.setAttribute("aria-expanded", open ? "true" : "false");
        });
    });

    const search = document.getElementById("global-search");
    document.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
            event.preventDefault();
            search?.focus();
        }
    });

    document.querySelectorAll("[data-copy]").forEach((button) => {
        button.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(button.dataset.copy || "");
                button.title = "Đã sao chép";
            } catch (_) { /* ignore */ }
        });
    });

    document.querySelectorAll("[data-open-dialog]").forEach((button) => {
        button.addEventListener("click", () => {
            document.getElementById(button.dataset.openDialog)?.showModal();
        });
    });
    document.querySelectorAll("[data-close-dialog]").forEach((button) => {
        button.addEventListener("click", () => button.closest("dialog")?.close());
    });

    /* Toasts: auto-close with a progress bar; hover or focus pauses the timer.
       Phải nằm TRƯỚC đoạn `if (!manager) return;` để chạy trên mọi trang. */
    document.querySelectorAll("[data-toast]").forEach((toast) => {
        const close = () => {
            if (toast.classList.contains("is-leaving")) return;
            toast.classList.add("is-leaving");
            toast.addEventListener("animationend", () => toast.remove(), { once: true });
            setTimeout(() => toast.remove(), 400);
        };
        toast.querySelector("[data-toast-close]")?.addEventListener("click", close);
        const total = Number(toast.dataset.timeout || 0);
        if (!total) return; // persistent (e.g. one-time password)
        const bar = toast.querySelector(".toast-progress");
        toast.querySelector("[data-toast-count]")?.remove(); // bỏ dòng "Đóng sau N giây"
        let remaining = total;
        let last = performance.now();
        let paused = false;
        const pause = () => { paused = true; };
        const resume = () => { paused = false; last = performance.now(); };
        toast.addEventListener("mouseenter", pause);
        toast.addEventListener("mouseleave", resume);
        toast.addEventListener("focusin", pause);
        toast.addEventListener("focusout", resume);
        const tick = (now) => {
            if (!toast.isConnected) return;
            if (!paused) {
                remaining -= now - last;
                if (remaining <= 0) { close(); return; }
            }
            last = now;
            if (bar) bar.style.transform = `scaleX(${Math.max(remaining, 0) / total})`;
            requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
    });

    /* User menu: bấm để mở/đóng, bấm ra ngoài hoặc nhấn Esc để đóng. */
    document.querySelectorAll("[data-user-menu]").forEach((menu) => {
        const toggle = menu.querySelector("[data-user-menu-toggle]");
        const panel = menu.querySelector(".user-dropdown");
        if (!toggle || !panel) return;

        const setOpen = (open) => {
            panel.hidden = !open;
            toggle.setAttribute("aria-expanded", open ? "true" : "false");
        };

        toggle.addEventListener("click", (event) => {
            event.stopPropagation();
            setOpen(panel.hidden);
        });
        document.addEventListener("click", (event) => {
            if (!menu.contains(event.target)) setOpen(false);
        });
        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && !panel.hidden) {
                setOpen(false);
                toggle.focus();
            }
        });
    });

    /* File manager: chỉ chạy trên trang có [data-file-manager]. */
    const manager = document.querySelector("[data-file-manager]");
    if (!manager) return;

    const table = manager.querySelector("[data-file-table]");
    const tbody = table?.querySelector("tbody");
    const rows = tbody ? Array.from(tbody.querySelectorAll("tr")) : [];
    const pageInfo = manager.querySelector("[data-page-info]");
    const pager = manager.querySelector("[data-pager]");
    const sortSelect = manager.querySelector("[data-sort]");
    const checkAll = manager.querySelector("[data-check-all]");
    const countEl = manager.querySelector("[data-selected-count]");
    const bulk = manager.querySelector(".fm-bulk");
    const pageSize = 10;
    let page = 1;
    let visible = rows.slice();

    const updateSelection = () => {
        const selected = rows.filter((row) => row.querySelector("input[name=paths]")?.checked).length;
        if (countEl) countEl.textContent = String(selected);
        bulk?.setAttribute("data-empty", selected ? "false" : "true");
    };

    const applyFilter = () => {
        const q = (search?.value || "").trim().toLowerCase();
        visible = rows.filter((row) => {
            const name = (row.dataset.name || "").toLowerCase();
            return !q || name.includes(q);
        });
        const sort = sortSelect?.value || "name-asc";
        visible.sort((a, b) => {
            const dir = (Number(b.dataset.dir) - Number(a.dataset.dir));
            if (sort.startsWith("name")) {
                const cmp = (a.dataset.name || "").localeCompare(b.dataset.name || "", "vi");
                return sort === "name-desc" ? -cmp : cmp;
            }
            const cmp = (b.dataset.date || "").localeCompare(a.dataset.date || "");
            return cmp || dir;
        });
        page = 1;
        renderPage();
    };

    const renderPage = () => {
        const total = visible.length;
        const pages = Math.max(1, Math.ceil(total / pageSize));
        if (page > pages) page = pages;
        const start = (page - 1) * pageSize;
        const slice = visible.slice(start, start + pageSize);
        rows.forEach((row) => { row.style.display = "none"; });
        slice.forEach((row) => { row.style.display = ""; });
        if (pageInfo) {
            const from = total ? start + 1 : 0;
            const to = start + slice.length;
            pageInfo.textContent = `Hiển thị ${from} - ${to} trong ${total} mục`;
        }
        if (pager) {
            pager.innerHTML = "";
            for (let i = 1; i <= pages; i += 1) {
                const btn = document.createElement("button");
                btn.type = "button";
                btn.textContent = String(i);
                if (i === page) btn.className = "current";
                btn.addEventListener("click", () => { page = i; renderPage(); });
                pager.appendChild(btn);
            }
        }
    };

    search?.addEventListener("input", applyFilter);
    sortSelect?.addEventListener("change", applyFilter);
    checkAll?.addEventListener("change", () => {
        visible.forEach((row) => {
            const box = row.querySelector("input[name=paths]");
            if (box && row.style.display !== "none") box.checked = checkAll.checked;
        });
        updateSelection();
    });
    tbody?.addEventListener("change", updateSelection);
    applyFilter();
    updateSelection();
})();