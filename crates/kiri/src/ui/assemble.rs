//! The window's page as every system loads it: index.html with its icons
//! and the terminal emulator (xterm.js, vendored unmodified in `xterm/`)
//! spliced into their placeholders. The Mac and Linux window (crates/kiri)
//! and Windows (kiri-win includes this file) load the same string, and
//! scripts/ui-test.py builds it the same way.
//!
//! Its words: the English keys and the one language it opens in (the
//! `lang` setting's, or the system's for System; `lang::strings_js`), and the
//! system's languages and the saved pick (`lang::boot_js`). Another language
//! comes when the page switches to it: the page sends `langwords` and the
//! host evaluates `lang::words_js`.
//!
//! The page is loaded as a string, and WebView2's NavigateToString takes at
//! most 2 MB. With xterm.js and the keys it is about 1.4 M UTF-16 units, and
//! a language adds its words: 40 to 60 K units. All of them would be well
//! past the limit, which is why the page carries only one.

const ICONS_JS: &str = include_str!("icons.js");
/// The languages and the first start's language step, which both pages show.
const LANGSTEP_JS: &str = include_str!("langstep.js");
const XTERM_CSS: &str = include_str!("xterm/xterm.css");
/// xterm.js 6.0.0 and its fit, search and web-links add-ons (UMD builds,
/// each defining a global), in the order they load.
const XTERM_JS: [&str; 4] = [include_str!("xterm/xterm.js"), include_str!("xterm/addon-fit.js"), include_str!("xterm/addon-search.js"), include_str!("xterm/addon-web-links.js")];

/// Windows' page: without what only the Mac and Linux windows have (between
/// `/*UNIX*/` and `/*/UNIX*/`, or `<!--UNIX-->` and `<!--/UNIX-->`: Servers,
/// Processes and the engine switcher, which kiri-win has no side for), and
/// with the stand-ins the shared code calls in their place (`/*WIN*` …
/// `*WIN*/`, a comment everywhere else). It keeps WebView2's page well
/// inside its limit for what Windows never shows.
pub fn for_windows(index: &str) -> String {
    let mut out = String::with_capacity(index.len());
    let mut rest = index;
    loop {
        let next = [("/*UNIX*/", "/*/UNIX*/"), ("<!--UNIX-->", "<!--/UNIX-->")].into_iter().filter_map(|(a, b)| rest.find(a).map(|i| (i, a, b))).min_by_key(|x| x.0);
        let Some((i, open, close)) = next else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..i]);
        let after = &rest[i + open.len()..];
        let end = after.find(close).unwrap_or(after.len());
        rest = after.get(end + close.len()..).unwrap_or("");
    }
    out.replace("/*WIN*", "").replace("*WIN*/", "")
}

/// `index` (index.html) with everything spliced in, `lang` (the `lang`
/// setting) picking its language. Windows' leaves out what only the Mac and
/// Linux windows have ([`for_windows`]).
pub fn page(index: &str, lang: Option<&str>) -> String {
    let windows;
    let index = if cfg!(windows) {
        windows = for_windows(index);
        windows.as_str()
    } else {
        index
    };
    let mut js = String::with_capacity(XTERM_JS.iter().map(|s| s.len() + 1).sum());
    for part in XTERM_JS {
        js.push_str(part);
        // Each ends in a source-map comment: the next must start on a line of its own.
        js.push('\n');
    }
    index
        .replacen("/*ICONS*/", ICONS_JS, 1)
        .replacen("/*LANGSTEP*/", LANGSTEP_JS, 1)
        .replacen("/*XTERM_CSS*/", XTERM_CSS, 1)
        .replacen("/*XTERM_JS*/", &js, 1)
        .replacen("/*LANG*/", &super::lang::boot_js(lang), 1)
        .replacen("/*STRINGS*/{}", &super::lang::strings_js(super::lang::resolve(lang)), 1)
}

/// A page that only needs its words and the language step spliced in
/// (kiri-win's setup page).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn words(page: &str, lang: Option<&str>) -> String {
    page.replacen("/*LANGSTEP*/", LANGSTEP_JS, 1).replacen("/*LANG*/", &super::lang::boot_js(lang), 1).replacen("/*STRINGS*/{}", &super::lang::strings_js(super::lang::resolve(lang)), 1)
}

#[cfg(test)]
mod tests {
    use super::super::lang;

    #[test]
    fn every_placeholder_is_filled_once_and_the_page_fits_webview2() {
        let units = |s: &str| s.encode_utf16().count();
        let page = super::page(include_str!("index.html"), None);
        for p in ["/*ICONS*/", "/*LANGSTEP*/", "/*XTERM_CSS*/", "/*XTERM_JS*/", "/*LANG*/", "/*STRINGS*/"] {
            assert!(!page.contains(p), "{p} left in the page");
        }
        assert!(page.contains(".xterm-viewport"), "xterm.css missing");
        assert!(page.contains("function langStep(") && page.contains("const LANGS = ["), "langstep.js missing");
        let setup = super::words(include_str!("../../../kiri-win/src/setup.html"), None);
        for p in ["/*LANGSTEP*/", "/*LANG*/", "/*STRINGS*/"] {
            assert!(!setup.contains(p), "{p} left in the setup page");
        }
        assert!(setup.contains("function langStep("), "langstep.js missing from the setup page");
        assert!(page.contains("window.KIRI_LANG = {") && page.contains(&lang::strings_js(lang::resolve(None))), "words missing");
        // Each language the page can open in carries the keys and that language
        // alone: the largest must stay well inside NavigateToString's 2 MB, with
        // room for the page to grow.
        let (mut worst, mut biggest) = (0, "");
        let windows = super::for_windows(include_str!("index.html"));
        for (tag, _) in lang::FILES {
            let p = super::page(&windows, Some(tag));
            assert!(p.contains(&lang::strings_js(tag)), "{tag}'s words missing");
            for (other, _) in lang::FILES {
                assert!(other == tag || !p.contains(&format!("\"{other}\":[")), "{tag}'s page carries {other} too");
            }
            if units(&p) > worst {
                (worst, biggest) = (units(&p), tag);
            }
        }
        // NavigateToString's limit is 2 MB; 1.8 M keeps a margin, and the worst
        // case stays 200 K under that (a language's words are about 60 K).
        assert!(worst + 200_000 < 1_800_000, "the page in {biggest} is {worst} UTF-16 units");
        assert!(units(&super::page(&windows, None)) <= worst);
        // Setup's page too.
        assert!(units(&super::words("/*LANG*/ /*STRINGS*/{}", Some(biggest))) < 200_000);
    }

    #[test]
    fn windows_page_leaves_the_unix_only_parts_out_and_stands_in_for_them() {
        let full = include_str!("index.html");
        let win = super::for_windows(full);
        for m in ["/*UNIX*/", "/*/UNIX*/", "<!--UNIX-->", "<!--/UNIX-->", "/*WIN*", "*WIN*/", "function renderServers() {\n", "id=\"engsw\"", "data-view=\"processes\""] {
            assert!(!win.contains(m), "{m} left in Windows' page");
        }
        assert!(win.contains("function srvCur() { return null; }") && win.contains("const tasksItem = () => \"\";"));
        assert!(full.contains("/*WIN*") && full.matches("/*UNIX*/").count() == full.matches("/*/UNIX*/").count());
        assert!(win.len() + 30_000 < full.len(), "the cut is what Windows never shows");
        // The rest is untouched: the shared views and the row polish stay.
        assert!(win.contains("function renderNetworks()") && win.contains("td.actions .acts-row { gap: 2px; }"));
    }
}
