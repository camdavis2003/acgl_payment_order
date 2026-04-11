/*
  Lightweight shell behavior for static/info pages.
  This avoids loading the full app monolith where data workflows are not needed.
*/

(() => {
  'use strict';

  const APP_TAB_TITLE = 'ACGL - FMS';
  const APP_VERSION = '1.0.0';
  const ACTIVE_BUDGET_YEAR_KEY = 'payment_order_active_budget_year_v1';
  const ACTIVE_BUDGET_YEAR_FALLBACK_KEY = 'payment_order_active_budget_year_local_v1';

  function getBasename(pathname) {
    const parts = String(pathname || '')
      .split('/')
      .filter(Boolean);
    return parts.length ? parts[parts.length - 1].toLowerCase() : 'index.html';
  }

  function readYearFromUrl() {
    try {
      const params = new URLSearchParams(window.location.search || '');
      const raw = String(params.get('year') || '').trim();
      if (/^\d{4}$/.test(raw)) return Number(raw);
    } catch {
      // ignore
    }
    return null;
  }

  function readStoredYear() {
    const parseYear = (raw) => {
      if (!/^\d{4}$/.test(raw)) return null;
      const y = Number(raw);
      if (!Number.isInteger(y)) return null;
      if (y < 1900 || y > 3000) return null;
      return y;
    };

    try {
      const raw = String(localStorage.getItem(ACTIVE_BUDGET_YEAR_KEY) || '').trim();
      const primary = parseYear(raw);
      if (primary) return primary;

      const fallbackRaw = String(localStorage.getItem(ACTIVE_BUDGET_YEAR_FALLBACK_KEY) || '').trim();
      const fallback = parseYear(fallbackRaw);
      if (fallback) return fallback;
    } catch {
      // ignore
    }
    return null;
  }

  function getActiveYear() {
    return readYearFromUrl() || readStoredYear() || new Date().getFullYear();
  }

  function withCurrentEmbedParams(href) {
    try {
      const current = new URL(window.location.href);
      const next = new URL(String(href || ''), current);
      const keep = ['wp', 'restUrl', 'restNonce'];
      for (const key of keep) {
        const value = current.searchParams.get(key);
        if (!value) continue;
        if (!next.searchParams.has(key)) next.searchParams.set(key, value);
      }
      return next.href;
    } catch {
      return String(href || '');
    }
  }

  function setAppTabTitle() {
    try {
      document.title = APP_TAB_TITLE;
    } catch {
      // ignore
    }

    try {
      if (window.top && window.top !== window) window.top.document.title = APP_TAB_TITLE;
    } catch {
      // ignore
    }

    try {
      if (window.parent && window.parent !== window) window.parent.document.title = APP_TAB_TITLE;
    } catch {
      // ignore
    }
  }

  function applyVersionLabel() {
    try {
      const els = document.querySelectorAll('[data-app-version]');
      for (const el of els) el.textContent = APP_VERSION;
    } catch {
      // ignore
    }
  }

  function initThemeToggle() {
    const themeToggle = document.getElementById('themeToggle');
    if (!themeToggle) return;

    const readTheme = () => {
      try {
        const t = String(localStorage.getItem('payment_order_theme') || '').trim();
        return t === 'dark' ? 'dark' : 'light';
      } catch {
        return 'light';
      }
    };

    const applyTheme = (theme) => {
      const t = String(theme || 'light') === 'dark' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', t);
      try {
        localStorage.setItem('payment_order_theme', t);
      } catch {
        // ignore
      }
      themeToggle.checked = t === 'dark';
    };

    applyTheme(readTheme());
    if (!themeToggle.dataset.boundTheme) {
      themeToggle.dataset.boundTheme = '1';
      themeToggle.addEventListener('change', () => {
        applyTheme(themeToggle.checked ? 'dark' : 'light');
      });
    }
  }

  // Returns true if the user has a valid WP session token (sessionStorage or
  // localStorage mirror written by app-request.js after sign-in).
  function isWpAuthenticated() {
    const sessionKey = 'acgl_fms_wp_token_v1';
    const userKey = 'payment_order_current_user_v1';
    let token = '';
    let username = '';
    try {
      token = String(sessionStorage.getItem(sessionKey) || '').trim();
      username = String(sessionStorage.getItem(userKey) || '').trim();
    } catch { /* ignore */ }
    try {
      // Walk up to the top-level window sessionStorage (same-origin iframe).
      if (window.top && window.top !== window && window.top.sessionStorage) {
        if (!token) token = String(window.top.sessionStorage.getItem(sessionKey) || '').trim();
        if (!username) username = String(window.top.sessionStorage.getItem(userKey) || '').trim();
      }
    } catch { /* ignore */ }

    // Some shell pages can be opened in contexts where the WP token is not
    // available but the signed-in username is still present.
    if (username && !token) return true;
    if (!token || !username) return false;

    const parts = token.split('.');
    if (parts.length < 2) return false;
    try {
      // JWT payload is segment #2. Keep a fallback to #1 for legacy/custom tokens.
      const decodePayloadPart = (rawPart) => {
        try {
          const b64 = String(rawPart || '').replace(/-/g, '+').replace(/_/g, '/');
          const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
          return JSON.parse(decodeURIComponent(escape(atob(padded))));
        } catch {
          return null;
        }
      };
      const payload = decodePayloadPart(parts[1]) || decodePayloadPart(parts[0]);
      if (!payload || typeof payload !== 'object') return false;
      const exp = Number(payload && payload.exp);
      if (Number.isFinite(exp) && (Date.now() / 1000) >= exp) return false;
    } catch {
      return false;
    }

    return true;
  }

  function initNavShell() {
    const shell = document.querySelector('[data-app-shell]');
    const nav = document.getElementById('appNav');
    const navTree = document.querySelector('[data-nav-tree]');
    const toggleBtn = document.getElementById('navToggle');
    if (!shell || !navTree) return;
    const currentBase = getBasename(window.location.pathname);

    const isAboutPopout = (() => {
      if (getBasename(window.location.pathname) !== 'about.html') return false;
      const winName = String(window.name || '').trim();
      if (winName !== 'acglAboutPopout') return false;
      try {
        const params = new URLSearchParams(window.location.search || '');
        return String(params.get('popout') || '').trim() === '1' && String(params.get('src') || '').trim() === 'request';
      } catch {
        return false;
      }
    })();

    if (isAboutPopout) {
      const siteHeader = document.querySelector('.site-header');
      if (siteHeader) {
        siteHeader.hidden = true;
        siteHeader.setAttribute('aria-hidden', 'true');
      }
      if (nav) {
        nav.hidden = true;
        nav.setAttribute('aria-hidden', 'true');
      }
      if (toggleBtn) {
        toggleBtn.hidden = true;
        toggleBtn.setAttribute('aria-hidden', 'true');
      }
      shell.classList.remove('appShell--navOpen');
      shell.classList.add('appShell--navClosed');
      return;
    }

    const isAuthenticated = isWpAuthenticated();

    // If the user is not authenticated, keep public pages minimal.
    // Exception: About should still render the usual app navigation unless
    // it is explicitly opened as the request popout (handled above).
    if (!isAuthenticated && currentBase !== 'about.html') {
      const ul = document.createElement('ul');
      ul.className = 'appNavTree__list';
      const li = document.createElement('li');
      li.className = 'appNavTree__item';
      const a = document.createElement('a');
      a.className = 'appNav__link appNavTree__link';
      a.textContent = 'New Request Form';
      a.href = withCurrentEmbedParams('index.html?new=1');
      li.appendChild(a);
      ul.appendChild(li);
      navTree.innerHTML = '';
      navTree.appendChild(ul);

      return;
    }

    const activeYear = getActiveYear();
    const links = [
      { label: 'New Request Form', href: 'index.html?new=1' },
      {
        label: 'Budget',
        href: `budget.html?year=${encodeURIComponent(String(activeYear))}`,
        children: [
          { label: 'Dashboard', href: `budget_dashboard.html?year=${encodeURIComponent(String(activeYear))}` },
        ],
      },
      {
        label: 'Ledger',
        href: `grand_secretary_ledger.html?year=${encodeURIComponent(String(activeYear))}`,
        children: [
          { label: 'BankEUR', href: `income.html?year=${encodeURIComponent(String(activeYear))}` },
          { label: 'wiseEUR', href: `wise_eur.html?year=${encodeURIComponent(String(activeYear))}` },
          { label: 'wiseUSD', href: `wise_usd.html?year=${encodeURIComponent(String(activeYear))}` },
        ],
      },
      {
        label: 'Payment Orders',
        href: `menu.html?year=${encodeURIComponent(String(activeYear))}`,
        children: [
          { label: 'Reconciliations', href: `reconciliation.html?year=${encodeURIComponent(String(activeYear))}` },
        ],
      },
      { label: 'Money Transfers', href: `money_transfers.html?year=${encodeURIComponent(String(activeYear))}` },
      { label: 'Archive', href: 'archive.html' },
      { label: 'Admin Settings', href: 'settings.html' },
      { label: 'User Guide', href: 'user_guide.html' },
      { label: 'Help Center', href: 'help.html' },
      { label: 'About', href: 'about.html' },
      { label: 'Log out', href: 'index.html?logout=1' },
    ];

    const ul = document.createElement('ul');
    ul.className = 'appNavTree__list';
    let idSeq = 0;

    for (const item of links) {
      const li = document.createElement('li');
      li.className = 'appNavTree__item';
      const children = Array.isArray(item.children) ? item.children : [];
      const isParent = children.length > 0;

      if (!isParent) {
        const a = document.createElement('a');
        a.className = 'appNav__link';
        a.textContent = item.label;
        a.href = withCurrentEmbedParams(item.href);
        if (getBasename(item.href) === currentBase) {
          a.classList.add('is-active');
          a.setAttribute('aria-current', 'page');
        }
        li.appendChild(a);
        ul.appendChild(li);
        continue;
      }

      const row = document.createElement('div');
      row.className = 'appNavTree__row';

      const parentLink = document.createElement('a');
      parentLink.className = 'appNav__link';
      parentLink.href = withCurrentEmbedParams(item.href);
      parentLink.textContent = item.label;

      const childList = document.createElement('ul');
      childList.className = 'appNavTree__children';
      idSeq += 1;
      childList.id = `shellNavChildren_${idSeq}`;

      let anyChildActive = false;
      for (const child of children) {
        const childLi = document.createElement('li');
        childLi.className = 'appNavTree__childItem';

        const childA = document.createElement('a');
        childA.className = 'appNav__sublink';
        childA.href = withCurrentEmbedParams(child.href);
        childA.textContent = child.label;

        if (getBasename(child.href) === currentBase) {
          anyChildActive = true;
          childA.classList.add('is-active');
          childA.setAttribute('aria-current', 'page');
        }

        childLi.appendChild(childA);
        childList.appendChild(childLi);
      }

      if (getBasename(item.href) === currentBase || anyChildActive) {
        parentLink.classList.add('is-active');
      }

      li.classList.remove('is-open');
      childList.hidden = true;

      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'appNavTree__toggle';
      toggle.setAttribute('aria-label', `Toggle ${item.label}`);
      toggle.setAttribute('aria-controls', childList.id);
      toggle.setAttribute('aria-expanded', 'false');
      toggle.textContent = '▸';
      toggle.addEventListener('click', (event) => {
        event.preventDefault();
        const nextOpen = !li.classList.contains('is-open');
        li.classList.toggle('is-open', nextOpen);
        childList.hidden = !nextOpen;
        toggle.setAttribute('aria-expanded', nextOpen ? 'true' : 'false');
      });

      row.appendChild(parentLink);
      row.appendChild(toggle);
      li.appendChild(row);
      li.appendChild(childList);
      ul.appendChild(li);
    }

    navTree.innerHTML = '';
    navTree.appendChild(ul);

    if (!toggleBtn) return;
    toggleBtn.hidden = false;

    const setOpen = (open) => {
      const nextOpen = Boolean(open);
      shell.classList.toggle('appShell--navOpen', nextOpen);
      shell.classList.toggle('appShell--navClosed', !nextOpen);
      toggleBtn.setAttribute('aria-expanded', nextOpen ? 'true' : 'false');
      toggleBtn.setAttribute('aria-label', nextOpen ? 'Close navigation' : 'Open navigation');
      if (nav) nav.setAttribute('aria-hidden', nextOpen ? 'false' : 'true');
    };

    setOpen(false);

    if (!toggleBtn.dataset.boundNavToggle) {
      toggleBtn.dataset.boundNavToggle = '1';
      toggleBtn.addEventListener('click', () => {
        const isOpen = shell.classList.contains('appShell--navOpen');
        setOpen(!isOpen);
      });
    }

    document.addEventListener('click', (event) => {
      if (!shell.classList.contains('appShell--navOpen')) return;
      if (toggleBtn.contains(event.target)) return;
      if (nav && nav.contains(event.target)) return;
      setOpen(false);
    });
  }

  function initPopoutLinks() {
    const links = Array.from(document.querySelectorAll('[data-popout-link="1"]'));
    if (!links.length) return;

    const features = 'popup=yes,noopener,noreferrer,width=1100,height=760,left=80,top=70,resizable=yes,scrollbars=yes';

    for (const a of links) {
      if (!a || a.dataset.popoutBound) continue;
      a.dataset.popoutBound = '1';
      a.addEventListener('click', (event) => {
        event.preventDefault();
        const href = String(a.getAttribute('href') || '').trim();
        if (!href) return;
        const name = String(a.getAttribute('data-popout-name') || 'acglPopout').trim() || 'acglPopout';
        const url = String(a.getAttribute('data-popout-external') || '').trim() === '1'
          ? href
          : withCurrentEmbedParams(href);
        try {
          const popup = window.open(url, name, features);
          if (popup && popup.focus) popup.focus();
        } catch {
          window.location.href = url;
        }
      });
    }
  }

  setAppTabTitle();
  applyVersionLabel();
  initThemeToggle();
  initNavShell();
  initPopoutLinks();
})();