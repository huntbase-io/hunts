// Product analytics for the public hub, in the same PostHog project as the
// website and the app. The hub has no consent banner, so nothing is stored on
// the visitor's device: no cookie, no localStorage, no session recording, no
// autocapture. Only the public build loads this file, and an embedded page
// (?embed=1) is measured by whatever embeds it. If PostHog is blocked, every
// call below lands in a queue nobody reads and the page carries on.
(() => {
  try {
    const me = document.currentScript;
    const key = me && me.dataset.key;
    if (!key || new URLSearchParams(location.search).has('embed')) return;

    // PostHog's loader: a stub that queues calls until array.js arrives.
    /* eslint-disable */
    !function(t,e){var o,n,p,r;e.__SV||(window.posthog=e,e._i=[],e.init=function(i,s,a){function g(t,e){var o=e.split(".");2==o.length&&(t=t[o[0]],e=o[1]),t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}}(p=t.createElement("script")).type="text/javascript",p.crossOrigin="anonymous",p.async=!0,p.src=s.api_host.replace(".i.posthog.com","-assets.i.posthog.com")+"/static/array.js",(r=t.getElementsByTagName("script")[0]).parentNode.insertBefore(p,r);var u=e;for(void 0!==a?u=e[a]=[]:a="posthog",u.people=u.people||[],u.toString=function(t){var e="posthog";return"posthog"!==a&&(e+="."+a),t||(e+=" (stub)"),e},u.people.toString=function(){return u.toString(1)+".people (stub)"},o="init capture register register_once unregister identify reset opt_in_capturing opt_out_capturing has_opted_out_capturing".split(" "),n=0;n<o.length;n++)g(u,o[n]);e._i.push([i,s,a])},e.__SV=1)}(document,window.posthog||[]);
    /* eslint-enable */

    posthog.init(key, {
      api_host: me.dataset.host,
      persistence: 'memory',
      person_profiles: 'identified_only',
      autocapture: false,
      capture_pageview: true,
      disable_session_recording: true,
      disable_surveys: true,
    });
    posthog.register({ app_source: 'hub', deployment: 'production' });

    const capture = (event, props) => { try { posthog.capture(event, props); } catch (e) { /* blocked */ } };
    const slug = (document.querySelector('article.hunt') || { dataset: {} }).dataset.slug;

    // One listener for every tracked link, including cards added after load.
    document.addEventListener('click', (e) => {
      const a = e.target.closest && e.target.closest('a');
      if (!a) return;
      const placement = a.dataset.placement || '';
      if (a.dataset.track === 'run') capture('hub_run_hunt_clicked', { slug, placement });
      else if (a.dataset.track === 'signup') capture('hub_signup_clicked', { placement });
      // A link to listmonk's hosted form: following it is the last thing the hub sees.
      else if (a.dataset.track === 'subscribe') capture('hub_subscribe_submitted', { placement, method: 'link' });
      else if (a.dataset.track === 'subscribe-jump') capture('hub_subscribe_cta_clicked', { placement });
      else if (a.hasAttribute('download')) capture('hub_download_clicked', { slug, file: a.getAttribute('href'), placement });
    }, true);

    // The inline forms post to listmonk themselves (see base.html); never the address.
    document.addEventListener('hub:subscribe', (e) => capture('hub_subscribe_submitted', { placement: e.detail.placement, method: 'form' }));

    // The home page says what a search found; wait for the typing to stop.
    let timer;
    document.addEventListener('hub:search', (e) => {
      clearTimeout(timer);
      if (e.detail.query_length) timer = setTimeout(() => capture('hub_search', e.detail), 1200);
    });

    // This file is deferred, so the first tab is already open by now.
    let tab = (document.querySelector('[data-tab][aria-selected="true"]') || { dataset: {} }).dataset.tab;
    if (slug && tab) capture('hub_tab_viewed', { slug, tab });
    document.addEventListener('hunt:tab', (e) => {
      if (e.detail === tab) return;
      tab = e.detail;
      capture('hub_tab_viewed', { slug, tab });
    });
  } catch (e) { /* analytics never break the page */ }
})();
