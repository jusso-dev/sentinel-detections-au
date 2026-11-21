# ASD and ACSC Advisory Sources and Licensing

This document records the public Australian Signals Directorate (ASD) Australian Cyber Security Centre (ACSC) advisory feeds and pages, their formats, copyright and terms of use, and the storage policy for this repository.

> This is an independent community project. It is not produced, endorsed or supported by ASD, the ACSC or Microsoft. Always verify current guidance on [cyber.gov.au](https://www.cyber.gov.au/).

## Public sources

ASD's ACSC publishes alerts, advisories and threat guidance on [cyber.gov.au](https://www.cyber.gov.au/) in both RSS 2.0 XML feeds and HTML pages.

| Source | URL | Format | Typical contents |
| --- | --- | --- | --- |
| Alerts RSS | `https://www.cyber.gov.au/rss/alerts` | RSS 2.0 XML (`application/rss+xml; charset=utf-8`) | High-priority security alerts (typically the 10 most recent items), including urgent vulnerability notices and active exploitation warnings |
| Advisories RSS | `https://www.cyber.gov.au/rss/advisories` | RSS 2.0 XML (`application/rss+xml; charset=utf-8`) | Joint and ASD cyber security advisories (typically the 5 most recent items), often containing threat actor TTPs, MITRE ATT&CK references and mitigation guidance |
| Threats RSS | `https://www.cyber.gov.au/rss/threats` | RSS 2.0 XML (`application/rss+xml; charset=utf-8`) | Threat and defensive guidance updates, including framework and OSCAL releases |
| News RSS | `https://www.cyber.gov.au/rss/news` | RSS 2.0 XML (`application/rss+xml; charset=utf-8`) | General cyber.gov.au news updates (not ingested for detections by default) |
| Alerts and advisories index | [Alerts and advisories](https://www.cyber.gov.au/alerts-and-advisories) | HTML (`text/html; charset=utf-8`) | Searchable listing of historical and current alerts and advisories (legacy path `/about-us/view-all-content/alerts-and-advisories` redirects with HTTP 301 to `/alerts-and-advisories`) |
| Individual alert pages | `https://www.cyber.gov.au/alert/<slug>` | HTML (`text/html; charset=utf-8`) | Full alert page, affected software, CVE identifiers and recommended mitigations |
| Individual advisory pages | `https://www.cyber.gov.au/advisory/<slug>` | HTML (`text/html; charset=utf-8`) | Full technical advisory page, TTP descriptions, MITRE ATT&CK techniques, indicators and linked PDFs |
| Information Security Manual (ISM) | [Information Security Manual](https://www.cyber.gov.au/ism) | HTML and OSCAL downloads | Official Australian Government cyber security controls used for mapping detections |

### RSS item structure

The `alerts` and `advisories` RSS 2.0 feeds expose standard `<item>` elements with the following fields:

- `<title>`: Advisory or alert headline.
- `<link>`: Canonical `https://www.cyber.gov.au/...` URL.
- `<description>`: Short plain or lightly marked-up summary.
- `<pubDate>`: RFC 2822 publication timestamp with Australian timezone offset (`+1000` or `+1100`).
- `<dc:creator>`: Author string (typically `Australian Cyber Security Centre (ACSC)`).
- `<guid isPermaLink="true">`: Canonical permalink matching `<link>`.

No public JSON API is documented for alerts and advisories on `cyber.gov.au`. Ingestion therefore uses the RSS 2.0 XML endpoints first, with polite, rate-limited fetching of canonical HTML pages only when extracting structured technical indicators or MITRE ATT&CK technique identifiers.

### Robots policy and polite fetching

The site publishes [robots.txt](https://www.cyber.gov.au/robots.txt). None of `/rss/`, `/alerts-and-advisories`, `/alert/` or `/advisory/` are disallowed. The automated watcher in this repository must still behave as a polite client:

- Poll no more frequently than once per day via scheduled workflow.
- Send a descriptive `User-Agent` header identifying this open-source project.
- Rate-limit page fetches (minimum delay between requests) and cap the number of new records processed per run.
- Cache or deduplicate by canonical URL and advisory identifier so previously seen items are not re-fetched unnecessarily.

## Copyright, licensing and terms of use

Per the [cyber.gov.au Copyright page](https://www.cyber.gov.au/copyright) (last reviewed 13 January 2026) and the [cyber.gov.au Disclaimer](https://www.cyber.gov.au/disclaimer):

1. **Default licence:** All material presented on `cyber.gov.au` is provided under a [Creative Commons Attribution 4.0 International licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0), unless otherwise noted.
2. **Required attribution:** Material obtained from `cyber.gov.au` must be attributed to the Australian Signals Directorate as Commonwealth of Australia with the publication year (for example, `Commonwealth of Australia 2026`, with the copyright symbol as shown on the official copyright page).
3. **Excluded material:** The CC BY 4.0 licence explicitly does **not** apply to:
   - The Commonwealth Coat of Arms.
   - The Australian Cyber Security Centre (ACSC) logo.
   - Content supplied by third parties (for example, joint partner materials or UK Crown Copyright material), where copyright remains with the third party.
   - Any other material explicitly stated not to be provided under CC BY 4.0.
4. **No endorsement:** Use of attribution or links to `cyber.gov.au` must not state or imply sponsorship, approval or endorsement by ASD, the ACSC or the Australian Government.

## Decision on what is stored in this repository

Although most original ASD content on `cyber.gov.au` is CC BY 4.0, joint advisories frequently incorporate third-party partner material and technical reports that may carry separate licence terms. To stay strictly compliant, lightweight and maintainable, this repository applies the following storage rule:

### Permitted to store

- **Metadata:** Advisory identifier (derived slug or official ID), title, publication date, source feed (`alerts` or `advisories`) and canonical `cyber.gov.au` URL.
- **Original summaries:** Concise summaries written in our own words (plain Australian English) describing why the advisory matters for Microsoft Sentinel and Microsoft Defender XDR defenders.
- **Structured technical mappings:** Factual identifiers extracted or curated for detection engineering:
  - MITRE ATT&CK technique and sub-technique IDs (for example `T1059.001`).
  - CVE identifiers and affected product names.
  - Published indicators of compromise (IOCs) when explicitly released as public defensive indicators, stored with source links and dates.
  - Relevant ASD Information Security Manual (ISM) control identifiers (by ID and short reference, linking to [cyber.gov.au/ism](https://www.cyber.gov.au/ism)).
  - Links to detection rules and hunting queries in this repository.
- **Attribution notice:** A standard reference to the official `cyber.gov.au` source URL and Commonwealth of Australia attribution where applicable.

### Not permitted to store

- **Full advisory text or scraped HTML/PDF mirrors:** Do not copy, mirror or archive full advisory bodies, PDFs or web pages in git. Always link to the canonical `cyber.gov.au` page.
- **Government emblems and logos:** Never store or display the Commonwealth Coat of Arms, ASD insignia, ACSC logo or Microsoft logos.
- **Unverified third-party content:** Do not reproduce third-party copyrighted tables or prose embedded in joint advisories.
- **Sensitive or live tenant data:** Never store real tenant IDs, subscription IDs, credentials, internal hostnames or customer incident data.

## References

- [ASD ACSC Alerts and advisories](https://www.cyber.gov.au/alerts-and-advisories)
- [ASD ACSC Copyright](https://www.cyber.gov.au/copyright)
- [ASD ACSC Disclaimer](https://www.cyber.gov.au/disclaimer)
- [ASD Information Security Manual (ISM)](https://www.cyber.gov.au/ism)
- [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/)
