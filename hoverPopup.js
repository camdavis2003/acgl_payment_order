(function () {
  'use strict';

  if (window.ACGLHoverPopup) return;

  const TOOLTIP_SELECTOR = '[data-tooltip], [data-po-tooltip], [data-role-tooltip], [title]';
  const margin = 12;
  const gap = 10;

  let tooltipEl = null;
  let activeTarget = null;
  let rafId = 0;

  function ensureTooltipEl() {
    if (tooltipEl) return tooltipEl;
    tooltipEl = document.createElement('div');
    tooltipEl.className = 'floatingTooltip';
    tooltipEl.setAttribute('role', 'tooltip');
    tooltipEl.style.display = 'none';
    document.body.appendChild(tooltipEl);
    return tooltipEl;
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function normalizeTooltipText(text) {
    return String(text || '').replace(/\s+/g, ' ').trim().toLowerCase();
  }

  function isBackLinkTarget(target) {
    if (!target) return false;
    const label = String((target.textContent || target.getAttribute('aria-label') || '')).trim();
    return /^\s*(?:←\s*)?back to\b/i.test(label);
  }

  function isAllowedButtonTooltip(target) {
    if (!target || target.tagName !== 'BUTTON') return true;
    if (target.id === 'budgetSetActiveBtn') return true;
    if (target.hasAttribute('data-allow-tooltip')) return true;
    return false;
  }

  function getTooltipText(target) {
    if (!target) return '';
    if (isBackLinkTarget(target)) return '';
    if (!isAllowedButtonTooltip(target)) return '';

    let text = '';
    if (target.hasAttribute('data-tooltip')) text = String(target.getAttribute('data-tooltip') || '').trim();
    else if (target.hasAttribute('data-po-tooltip')) text = String(target.getAttribute('data-po-tooltip') || '').trim();
    else if (target.hasAttribute('data-role-tooltip')) text = String(target.getAttribute('data-role-tooltip') || '').trim();
    else if (target.hasAttribute('title')) text = String(target.getAttribute('title') || '').trim();

    if (!text) return '';

    const isManagedOverflowTooltip = !!(target.dataset && target.dataset.teOverflowTooltipManaged === '1');
    const label = String(target.getAttribute('aria-label') || target.textContent || '').trim();
    if (!isManagedOverflowTooltip && normalizeTooltipText(text) && normalizeTooltipText(text) === normalizeTooltipText(label)) return '';
    return text;
  }

  function suppressNativeTitle(target) {
    if (!target || !target.hasAttribute || !target.hasAttribute('title')) return;
    if (!target.dataset.unifiedTooltipTitleBackup) {
      target.dataset.unifiedTooltipTitleBackup = String(target.getAttribute('title') || '');
    }
    target.removeAttribute('title');
  }

  function restoreNativeTitle(target) {
    if (!target || !target.dataset) return;
    if (!Object.prototype.hasOwnProperty.call(target.dataset, 'unifiedTooltipTitleBackup')) return;
    const backup = target.dataset.unifiedTooltipTitleBackup;
    if (backup) target.setAttribute('title', backup);
    delete target.dataset.unifiedTooltipTitleBackup;
  }

  function positionTooltipFor(target) {
    if (!target || !document.contains(target)) return;
    const text = getTooltipText(target);
    if (!text) return;

    suppressNativeTitle(target);

    const el = ensureTooltipEl();
    el.textContent = text;
    el.style.display = 'block';
    el.style.visibility = 'hidden';
    el.style.left = '0px';
    el.style.top = '0px';

    const targetRect = target.getBoundingClientRect();
    const tipRect = el.getBoundingClientRect();
    const maxLeft = window.innerWidth - margin - tipRect.width;
    const idealLeft = targetRect.left + (targetRect.width / 2) - (tipRect.width / 2);
    const left = clamp(idealLeft, margin, maxLeft);

    const belowTop = targetRect.bottom + gap;
    const aboveTop = targetRect.top - gap - tipRect.height;
    const fitsBelow = belowTop + tipRect.height <= window.innerHeight - margin;
    const fitsAbove = aboveTop >= margin;

    let top = fitsBelow || !fitsAbove ? belowTop : aboveTop;
    top = clamp(top, margin, window.innerHeight - margin - tipRect.height);

    el.style.left = `${Math.round(left)}px`;
    el.style.top = `${Math.round(top)}px`;
    el.style.visibility = 'visible';
  }

  function scheduleReposition() {
    if (!activeTarget || rafId) return;
    rafId = window.requestAnimationFrame(function () {
      rafId = 0;
      positionTooltipFor(activeTarget);
    });
  }

  function hide() {
    const lastTarget = activeTarget;
    activeTarget = null;
    if (rafId) {
      window.cancelAnimationFrame(rafId);
      rafId = 0;
    }
    if (tooltipEl) {
      tooltipEl.style.display = 'none';
      tooltipEl.textContent = '';
    }
    restoreNativeTitle(lastTarget);
  }

  function findTarget(node) {
    return node && node.closest ? node.closest(TOOLTIP_SELECTOR) : null;
  }

  function init() {
    if (window.__acglUnifiedHoverTooltipBound) return;
    window.__acglUnifiedHoverTooltipBound = true;

    document.addEventListener('mouseover', function (e) {
      const target = findTarget(e.target);
      if (!target) return;
      const text = getTooltipText(target);
      if (!text) return;
      if (activeTarget === target) return;
      if (activeTarget && activeTarget !== target) restoreNativeTitle(activeTarget);
      activeTarget = target;
      positionTooltipFor(activeTarget);
    });

    document.addEventListener('mouseout', function (e) {
      if (!activeTarget) return;
      const from = findTarget(e.target);
      if (!from || from !== activeTarget) return;
      const to = e.relatedTarget;
      if (to && from.contains && from.contains(to)) return;
      hide();
    });

    document.addEventListener('focusin', function (e) {
      const target = findTarget(e.target);
      if (!target) return;
      const text = getTooltipText(target);
      if (!text) return;
      if (activeTarget && activeTarget !== target) restoreNativeTitle(activeTarget);
      activeTarget = target;
      positionTooltipFor(activeTarget);
    });

    document.addEventListener('focusout', function (e) {
      if (!activeTarget) return;
      const from = findTarget(e.target);
      if (!from || from !== activeTarget) return;
      const to = e.relatedTarget;
      if (to && from.contains && from.contains(to)) return;
      hide();
    });

    document.addEventListener('pointermove', function (e) {
      if (!activeTarget) return;
      const hoverNode = document.elementFromPoint(e.clientX, e.clientY);
      if (hoverNode && activeTarget.contains(hoverNode)) return;

      const focused = document.activeElement;
      if (focused && (focused === activeTarget || activeTarget.contains(focused))) return;
      hide();
    }, { passive: true });

    window.addEventListener('resize', scheduleReposition);
    window.addEventListener('scroll', scheduleReposition, { passive: true, capture: true });
    window.__acglHideUnifiedHoverTooltip = hide;
  }

  function bindScope(scopeEl) {
    init();
    if (!scopeEl || !scopeEl.dataset || scopeEl.dataset.unifiedTooltipScopeBound) return;
    scopeEl.dataset.unifiedTooltipScopeBound = '1';
    scopeEl.addEventListener('scroll', function () {
      hide();
    }, { passive: true });
  }

  window.ACGLHoverPopup = {
    init,
    bindScope,
    hide,
    getTooltipText,
  };
})();