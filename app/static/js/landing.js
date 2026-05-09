/* ──────────────────────────────────────────────
   PhúNV Security — Landing Page Interactions
   ────────────────────────────────────────────── */
(function () {
  'use strict';

  function init() {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }

    initCounters();
    initScrambleCards();
    initGraphParallax();
    initMobileNav();
    initScrollSpy();
    initTimeChips();
  }

  /* ── Animated number counters ── */
  function animateCounter(el) {
    var target = parseFloat(el.dataset.count || '0');
    var suffix = el.dataset.suffix || '';
    var decimals = parseInt(el.dataset.decimal || '0', 10);
    var duration = 1600;
    var start = performance.now();

    function formatValue(v) {
      if (target >= 1000) {
        var value = Math.floor(v);
        return value >= 1000 ? (value / 1000).toFixed(1) + 'K' : String(value);
      }
      return (v).toFixed(decimals);
    }

    function step(now) {
      var progress = Math.min((now - start) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = formatValue(eased * target) + suffix;
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function initCounters() {
    var counters = document.querySelectorAll('[data-count]');
    if (!counters.length) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          animateCounter(e.target);
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.5 });
    counters.forEach(function (c) { io.observe(c); });
  }

  /* ── Scramble text effect on graph cards ── */
  var GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#@$%&*';

  function scrambleText(el) {
    var finalText = el.dataset.text || el.textContent.trim();
    if (!finalText) return;

    var frame = 0;
    var totalFrames = Math.max(10, finalText.length * 2);
    clearInterval(el._timer);
    el._timer = setInterval(function () {
      var next = '';
      for (var i = 0; i < finalText.length; i += 1) {
        var ch = finalText[i];
        if (ch === ' ') { next += ' '; continue; }
        if (i < frame / 2) { next += ch; }
        else { next += GLYPHS[Math.floor(Math.random() * GLYPHS.length)]; }
      }
      el.textContent = next;
      frame += 1;
      if (frame > totalFrames) {
        clearInterval(el._timer);
        el.textContent = finalText;
      }
    }, 24);
  }

  function initScrambleCards() {
    var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var cards = document.querySelectorAll('.scramble-card');
    cards.forEach(function (card) {
      var targets = card.querySelectorAll('.scramble-text');
      card.addEventListener('mouseenter', function () {
        targets.forEach(scrambleText);
      });
      if (prefersReduced) return;
      card.addEventListener('mouseleave', function () {
        card.style.transform = '';
      });
    });
  }

  /* ── Parallax on hero graph ── */
  function initGraphParallax() {
    var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var graph = document.getElementById('hero-graph');
    if (!graph || prefersReduced) return;

    var graphCards = graph.querySelectorAll('.graph-card');
    graph.addEventListener('mousemove', function (event) {
      var rect = graph.getBoundingClientRect();
      var dx = (event.clientX - rect.left - rect.width / 2) / rect.width;
      var dy = (event.clientY - rect.top - rect.height / 2) / rect.height;
      graphCards.forEach(function (card) {
        var depth = Number(card.dataset.depth || 1);
        var tx = dx * depth * 10;
        var ty = dy * depth * 8;
        card.style.transform = 'translate3d(' + tx + 'px, ' + ty + 'px, 0)';
      });
    });
    graph.addEventListener('mouseleave', function () {
      graphCards.forEach(function (card) { card.style.transform = ''; });
    });
  }

  /* ── Mobile hamburger navigation ── */
  function initMobileNav() {
    var toggle = document.querySelector('.nav-toggle');
    var menu = document.getElementById('nav-menu');
    var closeBtn = menu ? menu.querySelector('.nav-close') : null;
    if (!toggle || !menu) return;

    function closeMenu() {
      menu.classList.remove('is-open');
      toggle.classList.remove('is-open');
      toggle.setAttribute('aria-expanded', 'false');
      document.body.classList.remove('nav-open');
    }

    toggle.addEventListener('click', function () {
      var isOpen = menu.classList.toggle('is-open');
      toggle.classList.toggle('is-open', isOpen);
      toggle.setAttribute('aria-expanded', String(isOpen));
      document.body.classList.toggle('nav-open', isOpen);
    });

    if (closeBtn) {
      closeBtn.addEventListener('click', closeMenu);
    }

    menu.querySelectorAll('a').forEach(function (a) {
      a.addEventListener('click', closeMenu);
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeMenu();
    });
  }

  /* ── Scroll spy: highlight active nav link ── */
  function initScrollSpy() {
    var sections = Array.prototype.slice.call(document.querySelectorAll('section[id]'));
    var navLinks = Array.prototype.slice.call(document.querySelectorAll('.navbar-nav a[href^="#"]'));
    if (!sections.length || !navLinks.length) return;

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          var id = entry.target.id;
          navLinks.forEach(function (a) {
            a.classList.toggle('active', a.getAttribute('href') === '#' + id);
          });
        }
      });
    }, { rootMargin: '-45% 0px -45% 0px', threshold: 0 });

    sections.forEach(function (s) { io.observe(s); });
  }

  /* ── Time chip filters (visual only — demo) ── */
  function initTimeChips() {
    document.querySelectorAll('.lab-time-filter').forEach(function (group) {
      group.addEventListener('click', function (e) {
        var chip = e.target.closest && e.target.closest('.time-chip');
        if (!chip) return;
        group.querySelectorAll('.time-chip').forEach(function (c) {
          c.classList.remove('is-active');
        });
        chip.classList.add('is-active');
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
