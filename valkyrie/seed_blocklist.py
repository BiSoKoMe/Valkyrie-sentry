"""Seed blocklist — Valkyrie's built-in day-one protection.

A hardcoded set of the most egregious, universally-agreed tracking and
advertising domains.  Ships with the code: no download, no network, works
offline the instant Valkyrie starts.  While the intelligence layer spends
its learning period profiling the machine, this seed guarantees the
worst offenders are already sinkholed.

Matching semantics: every entry blocks the domain itself AND all of its
subdomains (``doubleclick.net`` also blocks ``ad.doubleclick.net``).

Curation rules — a domain is included only if it is:
  1. dedicated to tracking/ads/telemetry (not a mixed-use site), and
  2. present in effectively every mainstream blocklist
     (EasyPrivacy, StevenBlack, OISD, AdGuard), and
  3. safe to block without breaking the sites people actually visit.

That is why ``facebook.com`` or ``microsoft.com`` are NOT here, while
``pixel.facebook.com`` and ``telemetry.microsoft.com`` are.
"""

from __future__ import annotations

SEED_DOMAINS: frozenset[str] = frozenset({
    # ── Google advertising & tracking ─────────────────────────────────
    "doubleclick.net", "doubleclick.com", "googlesyndication.com",
    "googleadservices.com", "googletagmanager.com", "googletagservices.com",
    "google-analytics.com", "googleoptimize.com", "adservice.google.com",
    "pagead2.googlesyndication.com", "admob.com", "adsense.com",
    "2mdn.net", "app-measurement.com", "crashlytics.com",
    "doubleclickbygoogle.com", "googleadsserving.cn", "adwords.com",
    "urchin.com", "google-analytics.cn",

    # ── Meta / Facebook tracking (not the main site) ──────────────────
    "pixel.facebook.com", "an.facebook.com", "connect.facebook.net",
    "graph.instagram.com", "atdmt.com", "atlasdmt.com", "atlassolutions.com",
    "facebook-analytics.com", "fbsbx.com",

    # ── Amazon advertising ─────────────────────────────────────────────
    "amazon-adsystem.com", "amazonaax.com", "aax.amazon-adsystem.com",
    "a9.com", "serving.amazon-adsystem.com",

    # ── Microsoft / Windows telemetry ──────────────────────────────────
    "telemetry.microsoft.com", "vortex.data.microsoft.com",
    "vortex-win.data.microsoft.com", "watson.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com", "sqm.telemetry.microsoft.com",
    "df.telemetry.microsoft.com", "reports.wes.df.telemetry.microsoft.com",
    "services.wes.df.telemetry.microsoft.com", "telecommand.telemetry.microsoft.com",
    "telemetry.appex.bing.net", "telemetry.urs.microsoft.com",
    "self.events.data.microsoft.com", "v10.events.data.microsoft.com",
    "v10.vortex-win.data.microsoft.com", "v20.events.data.microsoft.com",
    "eu-mobile.events.data.microsoft.com", "us-mobile.events.data.microsoft.com",
    "browser.events.data.msn.com", "activity.windows.com",
    "settings-win.data.microsoft.com", "diagnostics.support.microsoft.com",
    "watson.microsoft.com", "wes.df.telemetry.microsoft.com",
    "telemetry.remoteapp.windowsazure.com", "vortex-sandbox.data.microsoft.com",
    "survey.watson.microsoft.com", "watson.live.com", "statsfe1.ws.microsoft.com",
    "statsfe2.ws.microsoft.com", "corpext.msitadfs.glbdns2.microsoft.com",
    "compatexchange.cloudapp.net", "cs1.wpc.v0cdn.net", "a-0001.a-msedge.net",
    "sls.update.microsoft.com.akadns.net", "diagnostics.data.microsoft.com",
    "feedback.windows.com", "feedback.microsoft-hohm.com", "feedback.search.microsoft.com",

    # ── Microsoft advertising / Bing / Clarity ─────────────────────────
    "bat.bing.com", "clarity.ms", "ads.msn.com", "adnexus.net",
    "ads1.msads.net", "ads2.msads.net", "aka-cdn-ns.adtech.de",
    "b.ads1.msn.com", "b.ads2.msads.net", "bingads.microsoft.com",

    # ── Apple telemetry (tracking endpoints only) ──────────────────────
    "metrics.apple.com", "metrics.icloud.com", "supportmetrics.apple.com",
    "metrics.mzstatic.com", "books-analytics-events.apple.com",
    "weather-analytics-events.apple.com", "notes-analytics-events.apple.com",

    # ── Comscore / audience measurement ────────────────────────────────
    "scorecardresearch.com", "comscore.com", "sitestat.com", "zqtk.net",
    "secure-us.imrworldwide.com", "nuggad.net", "meetrics.net",

    # ── Adobe marketing cloud ──────────────────────────────────────────
    "omtrdc.net", "2o7.net", "demdex.net", "everesttech.net",
    "adobedtm.com", "sitecatalyst.com", "hitbox.com", "207.net",

    # ── Oracle / BlueKai / AddThis data brokers ────────────────────────
    "bluekai.com", "bkrtx.com", "addthis.com", "addthisedge.com",
    "moatads.com", "moatpixel.com", "eloqua.com", "en25.com",
    "grapeshot.co.uk", "nexac.com",

    # ── Salesforce / Krux ──────────────────────────────────────────────
    "krxd.net", "exacttarget.com", "pardot.com",

    # ── Major ad exchanges & SSPs ──────────────────────────────────────
    "adnxs.com", "adsrvr.org", "rubiconproject.com", "pubmatic.com",
    "openx.net", "openx.com", "casalemedia.com", "indexww.com",
    "contextweb.com", "sonobi.com", "sovrn.com", "lijit.com",
    "sharethrough.com", "smartadserver.com", "spotxchange.com", "spotx.tv",
    "teads.tv", "triplelift.com", "yieldmo.com", "gumgum.com",
    "33across.com", "emxdgt.com", "loopme.me", "smaato.net",
    "bidswitch.net", "bidr.io", "adform.net", "adformdsp.net",
    "improvedigital.com", "yieldlab.net", "adscale.de", "stroeer.de",
    "criteo.com", "criteo.net", "hlserve.com", "adition.com",
    "districtm.io", "gothamads.com", "undertone.com", "unrulymedia.com",
    "tremorhub.com", "springserve.com", "beachfront.com", "telaria.com",
    "freewheel.tv", "stickyadstv.com", "innovid.com", "eyereturn.com",
    "adyoulike.com", "mgid.com", "revcontent.com", "content-ad.net",
    "onetag-sys.com", "richaudience.com", "seedtag.com", "sunmedia.tv",
    "e-planning.net", "adkernel.com", "adpone.com", "luponmedia.com",

    # ── Retargeting / DSPs ─────────────────────────────────────────────
    "adroll.com", "quantserve.com", "quantcast.com", "mathtag.com",
    "turn.com", "amobee.com", "adsymptotic.com", "simpli.fi",
    "dotomi.com", "conversantmedia.com", "mediamath.com", "rfihub.com",
    "steelhousemedia.com", "perfectaudience.com", "chango.com",
    "retargetly.com", "dstillery.com", "media6degrees.com",
    "zemanta.com", "outbrain.com", "taboola.com", "ligadx.com",

    # ── Identity graphs / data brokers ─────────────────────────────────
    "rlcdn.com", "liveramp.com", "acxiom.com", "pippio.com",
    "tapad.com", "agkn.com", "crwdcntrl.net", "eyeota.net",
    "exelator.com", "owneriq.net", "mookie1.com", "adentifi.com",
    "narrative.io", "audiencerate.com", "adsquare.com", "zeotap.com",
    "throtle.io", "infutor.com", "fullcontact.com", "towerdata.com",

    # ── Session replay / heatmaps / product analytics ──────────────────
    "hotjar.com", "hotjar.io", "mouseflow.com", "fullstory.com",
    "logrocket.com", "logrocket.io", "lr-ingest.io", "lr-in.com",
    "inspectlet.com", "luckyorange.com", "luckyorange.net",
    "smartlook.com", "smartlook.cloud", "clicktale.net", "sessioncam.com",
    "crazyegg.com", "decibelinsight.net", "contentsquare.net",
    "quantummetric.com", "glassboxdigital.io", "userzoom.com",

    # ── Web / product analytics platforms ──────────────────────────────
    "mixpanel.com", "mxpnl.com", "segment.com", "segment.io",
    "amplitude.com", "heapanalytics.com", "heap.io", "kissmetrics.com",
    "kissmetrics.io", "statcounter.com", "chartbeat.com", "chartbeat.net",
    "parsely.com", "parse.ly", "gosquared.com", "woopra.com",
    "matomo.cloud", "histats.com", "clicky.com", "getclicky.com",
    "gauges.com", "goingup.com", "reinvigorate.net", "w3counter.com",
    "sitemeter.com", "onestat.com", "opentracker.net", "hitslink.com",
    "extreme-dm.com", "hittail.com", "webtrends.com", "webtrendslive.com",

    # ── Tag managers / CDPs (tracking-dedicated) ───────────────────────
    "tealiumiq.com", "tealium.com", "tiqcdn.com", "ensighten.com",
    "signal.co", "brighttag.com", "commandersact.com", "tagcommander.com",
    "qubit.com", "usabilla.com", "mparticle.com", "rudderstack.com",

    # ── A/B testing & personalisation trackers ─────────────────────────
    "optimizely.com", "abtasty.com", "vwo.com", "visualwebsiteoptimizer.com",
    "convert.com", "kameleoon.com", "dynamicyield.com", "evergage.com",
    "monetate.net", "sailthru.com", "bounceexchange.com", "bouncex.net",
    "wunderkind.co", "attentivemobile.com", "listrakbi.com",

    # ── Mobile attribution & app trackers ──────────────────────────────
    "adjust.com", "adjust.io", "appsflyer.com", "kochava.com",
    "branch.io", "singular.net", "tenjin.io", "airbridge.io",
    "apptentive.com", "leanplum.com", "clevertap-prod.com", "clevertap.com",
    "swrve.com", "mobileapptracking.com", "tune.com", "hasoffers.com",
    "apsalar.com", "localytics.com", "flurry.com", "tapjoy.com",
    "tapjoyads.com", "supersonicads.com", "ironsrc.com", "ironsrc.mobi",
    "applovin.com", "applvn.com", "chartboost.com", "vungle.com",
    "unityads.unity3d.com", "inmobi.com", "inmobicdn.net", "startappservice.com",
    "startapp.com", "mintegral.com", "mintegral.net", "pubnative.net",
    "fyber.com", "inner-active.mobi", "adcolony.com", "mopub.com",
    "millennialmedia.com", "jumptap.com", "amazon-mobile-analytics.com",

    # ── Push / engagement trackers ─────────────────────────────────────
    "pushwoosh.com", "pushcrew.com", "pusherism.com", "izooto.com",
    "moengage.com", "notifyvisitors.com",

    # ── Ad verification / viewability ──────────────────────────────────
    "doubleverify.com", "adsafeprotected.com", "iasds01.com",
    "serving-sys.com", "sizmek.com", "flashtalking.com", "adsafety.net",
    "adloox.com", "meetrics.com", "onad.eu", "protected.media",

    # ── Affiliate & click trackers ─────────────────────────────────────
    "awin1.com", "zanox.com", "linksynergy.com", "cj.com",
    "commission-junction.com", "shareasale.com", "impactradius.com",
    "impactradius-event.com", "go2cloud.org", "avantlink.com",
    "pepperjamnetwork.com", "clickbank.net", "hop.clickbank.net",
    "voluum.com", "bemobtrcks.com", "clicktripz.com", "skimresources.com",
    "viglink.com", "redirectingat.com", "anrdoezrs.net", "dpbolvw.net",
    "jdoqocy.com", "kqzyfj.com", "tkqlhce.com", "qksrv.net",
    "emjcd.com", "afcyhf.com", "awltovhc.com", "ftjcfx.com",
    "lduhtrp.net", "tqlkg.com", "yceml.net",

    # ── Pop / redirect / aggressive ad networks ────────────────────────
    "popads.net", "popcash.net", "propellerads.com", "propellerclick.com",
    "adcash.com", "adsterra.com", "hilltopads.net", "clickadu.com",
    "exoclick.com", "exosrv.com", "juicyads.com", "trafficjunky.com",
    "trafficfactory.biz", "adnium.com", "plugrush.com", "ero-advertising.com",
    "adspyglass.com", "mobtop.com", "richpush.co", "pushground.com",
    "evadav.com", "coinzilla.com", "cointraffic.io", "a-ads.com",
    "revenuehits.com", "yllix.com", "bidvertiser.com", "adf.ly",
    "linkbucks.com", "shorte.st", "ouo.io",

    # ── Cryptomining trackers ──────────────────────────────────────────
    "coinhive.com", "coin-hive.com", "cryptoloot.pro", "crypto-loot.com",
    "webminepool.com", "minero.cc", "coinimp.com", "hashing.win",

    # ── Fingerprinting services ────────────────────────────────────────
    "iovation.com", "threatmetrix.com", "online-metrix.net",

    # ── Email open/click trackers (dedicated pixel hosts) ──────────────
    "sendibt3.com", "mailtrack.io", "yesware.com", "bananatag.com",

    # ── Yandex / RU trackers ───────────────────────────────────────────
    "mc.yandex.ru", "an.yandex.ru", "adfox.ru", "yadro.ru",
    "top100.rambler.ru", "counter.rambler.ru", "liveinternet.ru",
    "top.mail.ru", "tns-counter.ru", "mediascope.net",

    # ── Chinese trackers ───────────────────────────────────────────────
    "cnzz.com", "umeng.com", "umengcloud.com", "hm.baidu.com",
    "pos.baidu.com", "cpro.baidu.com", "talkingdata.com", "talkingdata.net",
    "growingio.com", "getui.com", "igexin.com", "jpush.cn",
    "gridsumdissector.com", "miaozhen.com", "irs01.com", "irs09.com",
    "mmstat.com", "alimama.com", "tanx.com", "gepush.com",

    # ── Smart-TV / OEM telemetry ───────────────────────────────────────
    "ads.samsung.com", "lgad.cjpowercast.com", "lgsmartad.com",
    "alphonso.tv", "samba.tv", "sambatv.com", "tvsquared.com",

    # ── Consent-bypass / cookie-wall trackers ──────────────────────────

    # ── Misc universally-blocked trackers ──────────────────────────────
    "chango.ca", "effectivemeasure.net", "ipredictive.com",
    "intentiq.com", "permutive.com", "permutive.app", "primis.tech",
    "connatix.com", "ex.co", "playbuzz.com", "vidazoo.com",
    "aniview.com", "avantisvideo.com", "brid.tv", "vidoomy.com",
    "seedtag.io", "insurads.com", "adman.gr", "adman.otenet.gr",
    "twcount.com", "hexagon-analytics.com", "cedexis.com", "cedexis-radar.net",
    "summerhamster.com", "pool-x.eu", "adition.net",
    "1rx.io", "rhythmone.com", "rhythmxchange.com", "burt.io",
    "richrelevance.com", "monetate.com", "certona.net", "barilliance.net",
    "granify.com", "reflektion.com", "unbxd.io", "klevu.com",
    "attraqt.com", "findify.io", "nosto.com", "clerk.io",
    "webgains.com", "profitshare.ro", "2parale.ro", "dwin1.com",
    "belboon.com", "tradedoubler.com", "tradetracker.net", "daisycon.io",
    "kwanko.com", "effiliation.com", "timeone.io", "netaffiliation.com",

    # ── Bucket-A widening (SIGNAL_DESIGN_REPORT.md) ─────────────────────
    # Dedicated tracker/ad/analytics registrable domains confirmed by
    # EasyPrivacy and previously novel to Valkyrie. Each is a pure-purpose
    # tracking domain (not a mixed-use site), so listing the eTLD+1 blocks all
    # its subdomains without breaking anything users visit — same curation
    # rules as the rest of this file. Adding these closes the Bucket-A misses
    # with no new detection logic and no false-positive risk.
    #   media.net             — contextual-ad network (covers cs.media.net)
    #   sharethis.com         — share-widget tracker (covers l./seg./count-server.)
    #   taboolasyndication.com — Taboola ad syndication
    #   segmentapis.com       — Segment/Twilio CDP ingest API
    #   browser-intake-datadoghq.com — Datadog RUM ingest (dedicated, not the app)
    #   posthog.com / plausible.io   — product-analytics vendors (cf. mixpanel/segment above)
    #   fingerprint.com       — FingerprintJS device fingerprinting
    #   brandmetrics.com / adalytics.io — ad measurement / analytics
    # NOTE: ceros.com was classified Bucket-A but is HELD BACK — Ceros serves
    # user-facing embedded interactive content, so blocking its eTLD+1 could
    # break real page content (violates curation rule #3). It needs an exact
    # tracker-host entry, not an eTLD+1 block; left out pending that curation.
    "media.net", "sharethis.com", "taboolasyndication.com",
    "segmentapis.com", "browser-intake-datadoghq.com",
    "posthog.com", "plausible.io", "fingerprint.com",
    "brandmetrics.com", "adalytics.io",
})


def seed_count() -> int:
    """Number of seed domains shipped with this build."""
    return len(SEED_DOMAINS)
