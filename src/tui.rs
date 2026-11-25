//! The terminal look shared by `scan`, `plan` and `compare`: one rounded frame with
//! the tool's name as a tab, an inner box for what ran, and section tabs joined to
//! the left border. One accent color, red for blockers only, bold and dim for the
//! rest. Without a terminal it prints ASCII without color, so logs and goldens stay
//! plain. The spinner on stderr shows what a run is doing while it runs.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How the summary may draw. Glyphs need a terminal; color additionally honours
/// `NO_COLOR`.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub color: bool,
    pub unicode: bool,
    /// 24-bit color (`COLORTERM=truecolor`), else the 256-color palette.
    pub truecolor: bool,
    /// Columns the frame takes, the terminal width within [`MIN_WIDTH`, `MAX_WIDTH`].
    pub width: usize,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            color: false,
            unicode: false,
            truecolor: false,
            width: MAX_WIDTH,
        }
    }
}

pub const MAX_WIDTH: usize = 100;
pub const MIN_WIDTH: usize = 72;

impl Style {
    /// The style for stderr as it is now.
    pub fn for_stderr() -> Self {
        let unicode = std::io::stderr().is_terminal();
        let width = terminal_width()
            .unwrap_or(MAX_WIDTH)
            .clamp(MIN_WIDTH, MAX_WIDTH);
        Self {
            unicode,
            color: unicode && std::env::var_os("NO_COLOR").is_none(),
            truecolor: std::env::var("COLORTERM")
                .is_ok_and(|v| v.contains("truecolor") || v.contains("24bit")),
            width,
        }
    }
}

#[cfg(unix)]
fn terminal_width() -> Option<usize> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct Winsize {
        rows: u16,
        cols: u16,
        x: u16,
        y: u16,
    }
    unsafe extern "C" {
        fn ioctl(fd: i32, request: std::ffi::c_ulong, ...) -> i32;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const TIOCGWINSZ: std::ffi::c_ulong = 0x5413;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const TIOCGWINSZ: std::ffi::c_ulong = 0x4008_7468;
    let mut w = Winsize {
        rows: 0,
        cols: 0,
        x: 0,
        y: 0,
    };
    // SAFETY: TIOCGWINSZ writes one `winsize` into the pointer, which lives for the call.
    let ok = unsafe { ioctl(std::io::stderr().as_raw_fd(), TIOCGWINSZ, &mut w) } == 0;
    (ok && w.cols > 0).then_some(usize::from(w.cols))
}

#[cfg(not(unix))]
fn terminal_width() -> Option<usize> {
    std::env::var("COLUMNS").ok()?.parse().ok()
}

/// Where the JSON report went, for the last line of the summary.
#[derive(Debug, Clone, Default)]
pub enum Destination {
    File(String),
    Stdout,
    #[default]
    Nowhere,
}

/// What the summary says about the run itself.
#[derive(Debug, Clone, Default)]
pub struct Run {
    pub elapsed: Option<Duration>,
    pub json: Destination,
}

/// Text segments: `(r, g, b)` with the 256-color fallback.
const ACCENT: ((u8, u8, u8), u8) = ((64, 196, 176), 79);
const RED: ((u8, u8, u8), u8) = ((255, 107, 128), 204);
const ON_ACCENT: ((u8, u8, u8), u8) = ((10, 25, 25), 233);

/// Paints and draws in one style.
#[derive(Clone, Copy)]
pub struct Pen {
    pub st: Style,
}

impl Pen {
    pub fn new(st: Style) -> Self {
        Self { st }
    }

    pub fn g(&self, uni: &'static str, ascii: &'static str) -> &'static str {
        if self.st.unicode { uni } else { ascii }
    }

    fn rgb(&self, (c, n): ((u8, u8, u8), u8), bg: bool) -> String {
        let k = if bg { 48 } else { 38 };
        if self.st.truecolor {
            format!("{k};2;{};{};{}", c.0, c.1, c.2)
        } else {
            format!("{k};5;{n}")
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.st.color && !text.is_empty() {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn acc(&self, s: &str) -> String {
        self.paint(&self.rgb(ACCENT, false), s)
    }
    pub fn red(&self, s: &str) -> String {
        self.paint(&self.rgb(RED, false), s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    pub fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }

    /// A title on a border: a filled accent tab in color, else the plain title.
    pub fn tab(&self, title: &str) -> String {
        if self.st.color {
            let code = format!(
                "1;{};{}",
                self.rgb(ON_ACCENT, false),
                self.rgb(ACCENT, true)
            );
            self.paint(&code, &format!(" {title} "))
        } else {
            format!(" {title} ")
        }
    }

    /// A code replacement: accent in color, else in backticks.
    pub fn code(&self, s: &str) -> String {
        if self.st.color {
            self.acc(s)
        } else {
            format!("`{s}`")
        }
    }

    pub fn block(&self) -> String {
        self.red(self.g("✘", "x"))
    }
    pub fn act(&self) -> String {
        self.acc(self.g("●", "*"))
    }
    pub fn ok(&self) -> String {
        self.acc(self.g("✔", "+"))
    }
    pub fn verify(&self) -> String {
        "?".into()
    }
    pub fn note(&self) -> String {
        self.acc("!")
    }
    pub fn arrow(&self) -> &'static str {
        self.g("→", "->")
    }
    pub fn elbow(&self) -> String {
        self.dim(self.g("└", "`-"))
    }
    pub fn dot(&self) -> &'static str {
        self.g(" · ", " - ")
    }
    pub fn ellipsis(&self) -> &'static str {
        self.g("…", "~")
    }
    pub fn times(&self, n: usize) -> String {
        if self.st.unicode {
            format!("×{n}")
        } else {
            format!("x{n}")
        }
    }
}

/// The columns `s` takes: characters outside escape sequences.
pub fn width(s: &str) -> usize {
    let mut n = 0;
    let mut esc = false;
    for c in s.chars() {
        match (esc, c) {
            (false, '\x1b') => esc = true,
            (true, 'm') => esc = false,
            (true, _) => {}
            (false, _) => n += 1,
        }
    }
    n
}

/// `s` cut to `max` columns, escape sequences kept, with `ellipsis` where it was cut.
pub fn fit(s: &str, max: usize, ellipsis: &str) -> String {
    if width(s) <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(width(ellipsis));
    let (mut out, mut n, mut esc, mut open) = (String::new(), 0, false, false);
    for c in s.chars() {
        if esc {
            out.push(c);
            if c == 'm' {
                esc = false;
            }
            continue;
        }
        if c == '\x1b' {
            esc = true;
            open = true;
            out.push(c);
            continue;
        }
        if n == keep {
            break;
        }
        out.push(c);
        n += 1;
    }
    out.push_str(ellipsis);
    if open {
        out.push_str("\x1b[0m");
    }
    out
}

pub fn pad(s: &str, w: usize) -> String {
    let n = width(s);
    format!("{s}{}", " ".repeat(w.saturating_sub(n)))
}

/// Greedy word wrap; a word longer than the width stays whole on its own line.
pub fn wrap(text: &str, w: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && width(&cur) + 1 + width(word) > w {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

enum Row {
    Line(String),
    Section { title: String, right: String },
    Boxed(Vec<String>),
}

/// The summary as rows, drawn in one frame by [`Frame::render`].
pub struct Frame {
    pub pen: Pen,
    rows: Vec<Row>,
}

impl Frame {
    pub fn new(st: Style) -> Self {
        Self {
            pen: Pen::new(st),
            rows: Vec::new(),
        }
    }

    /// Columns available inside the frame.
    pub fn inner(&self) -> usize {
        self.pen.st.width - 4
    }

    pub fn line(&mut self, s: impl Into<String>) {
        self.rows.push(Row::Line(s.into()));
    }

    pub fn blank(&mut self) {
        self.line(String::new());
    }

    /// `text` as it is when it fits, else wrapped like [`Frame::para`].
    pub fn fitted(&mut self, lead: &str, text: &str) {
        if width(lead) + width(text) <= self.inner() {
            self.line(format!("{lead}{text}"));
        } else {
            self.para(lead, text);
        }
    }

    /// Prose wrapped to the frame, the first line after `lead`, the rest under it.
    pub fn para(&mut self, lead: &str, text: &str) {
        let indent = width(lead);
        for (i, l) in wrap(text, self.inner() - indent).into_iter().enumerate() {
            let head = if i == 0 {
                lead.to_string()
            } else {
                " ".repeat(indent)
            };
            self.line(format!("{head}{l}"));
        }
    }

    /// A section tab joined to the left border, with `right` at the right edge.
    pub fn section(&mut self, title: &str, right: impl Into<String>) {
        self.rows.push(Row::Section {
            title: title.into(),
            right: right.into(),
        });
    }

    pub fn boxed(&mut self, lines: Vec<String>) {
        self.rows.push(Row::Boxed(lines));
    }

    pub fn render(&self, title: &str) -> String {
        let p = &self.pen;
        let (w, inner) = (p.st.width, self.inner());
        let h = p.g("─", "-");
        let v = p.acc(p.g("│", "|"));
        let (tl, tr, bl, br, tee) = (
            p.g("╭", "+"),
            p.g("╮", "+"),
            p.g("╰", "+"),
            p.g("╯", "+"),
            p.g("├", "+"),
        );
        let ell = p.ellipsis();
        let row =
            |left: &str, body: &str| format!("{left}{} {v}", pad(&fit(body, inner, ell), inner));
        let head = format!("{}{}", p.acc(&format!("{tl}{h}")), p.tab(title));
        let mut out = vec![format!(
            "{head}{}",
            p.acc(&format!(
                "{}{tr}",
                h.repeat(w.saturating_sub(width(&head) + 1))
            ))
        )];
        let plain = format!("{v} ");
        for r in &self.rows {
            match r {
                Row::Line(l) => out.push(row(&plain, l)),
                Row::Section { title, right } => {
                    let t = p.tab(title);
                    let right = p.dim(right);
                    let gap = inner.saturating_sub(width(&t) + width(&right));
                    out.push(row(
                        &p.acc(&format!("{tee}{h}")),
                        &format!("{t}{}{right}", " ".repeat(gap)),
                    ));
                }
                Row::Boxed(lines) => {
                    let iw = inner;
                    out.push(row(
                        &plain,
                        &p.acc(&format!("{tl}{}{tr}", h.repeat(iw - 2))),
                    ));
                    for l in lines {
                        let body = pad(&fit(l, iw - 4, ell), iw - 4);
                        out.push(row(
                            &plain,
                            &format!("{} {body} {}", p.acc(p.g("│", "|")), p.acc(p.g("│", "|"))),
                        ));
                    }
                    out.push(row(
                        &plain,
                        &p.acc(&format!("{bl}{}{br}", h.repeat(iw - 2))),
                    ));
                }
            }
        }
        out.push(p.acc(&format!("{bl}{}{br}", h.repeat(w - 2))));
        out.join("\n") + "\n"
    }
}

/// The last line: where the JSON report is, or how to get it.
pub fn json_line(p: &Pen, run: &Run, hint: Option<&str>) -> String {
    let hint = hint.map(|h| format!("   {}", p.dim(h))).unwrap_or_default();
    match &run.json {
        Destination::File(path) => format!("{}  {path}{hint}", p.dim("JSON report")),
        Destination::Stdout => format!("{}  stdout{hint}", p.dim("JSON report")),
        Destination::Nowhere => format!(
            "{}  add {}, or pipe stdout {}",
            p.dim("JSON report not written"),
            p.acc("--out report.json"),
            p.dim("(| jq, > file)")
        ),
    }
}

/// `3.1s`, or `2m 05s` from one minute on.
pub fn elapsed(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 60.0 {
        format!("{s:.1}s")
    } else {
        format!("{}m {:02}s", d.as_secs() / 60, d.as_secs() % 60)
    }
}

/// The construct path or logical id, short enough to name a resource: no stack,
/// no `/Resource` or `/Default` leaf, at most the last three parts.
pub fn short_id(logical_id: &str, cdk_path: Option<&str>) -> String {
    let full = cdk_path.unwrap_or(logical_id);
    let mut parts: Vec<&str> = full.split('/').collect();
    while parts.len() > 1 && matches!(parts.last(), Some(&"Resource" | &"Default")) {
        parts.pop();
    }
    // Template sections name themselves; a CDK id starts with its stack.
    let section = ["Outputs", "Globals", "Parameters"].contains(&parts[0]);
    if parts.len() > 1 && !section && (cdk_path.is_some() || !logical_id.contains('.')) {
        parts.remove(0);
    }
    let n = parts.len();
    parts[n.saturating_sub(3)..].join("/")
}

struct Spin {
    phase: Arc<Mutex<String>>,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

static SPIN: Mutex<Option<Spin>> = Mutex::new(None);
/// Held while a line is written, so the spinner never draws into it.
static OUT: Mutex<()> = Mutex::new(());

/// Starts the spinner on stderr when it is a terminal: `title`, the current phase
/// and the elapsed time, redrawn every 80ms until [`stop`].
pub fn start(title: &str, enabled: bool) {
    if !enabled || !std::io::stderr().is_terminal() {
        return;
    }
    let pen = Pen::new(Style::for_stderr());
    let phase = Arc::new(Mutex::new(String::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (ph, st, title) = (phase.clone(), stop.clone(), title.to_string());
    let thread = std::thread::spawn(move || {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let t0 = Instant::now();
        let mut i = 0;
        while !st.load(Ordering::Relaxed) {
            let phase = ph.lock().map(|p| p.clone()).unwrap_or_default();
            // The elapsed time before the phase, so a narrow terminal cuts the phase.
            let mut line = format!(
                "{} {}  {}",
                pen.acc(FRAMES[i % FRAMES.len()]),
                pen.bold(&title),
                pen.dim(&elapsed(t0.elapsed()))
            );
            if !phase.is_empty() {
                line.push_str(&format!("  {}  {phase}", pen.dim("·")));
            }
            // The real width, so the line never wraps and leaves rows behind.
            let cols = terminal_width().unwrap_or(MAX_WIDTH).max(20);
            let line = fit(&line, cols - 1, "…");
            if let Ok(_g) = OUT.lock() {
                let mut e = std::io::stderr().lock();
                let _ = write!(e, "\r\x1b[2K{line}");
                let _ = e.flush();
            }
            i += 1;
            std::thread::sleep(Duration::from_millis(80));
        }
        let _ = write!(std::io::stderr().lock(), "\r\x1b[2K");
    });
    if let Ok(mut s) = SPIN.lock() {
        *s = Some(Spin {
            phase,
            stop,
            thread,
        });
    }
}

/// What the run does now, for the spinner.
pub fn phase(text: impl Into<String>) {
    if let Ok(s) = SPIN.lock()
        && let Some(s) = s.as_ref()
        && let Ok(mut p) = s.phase.lock()
    {
        *p = text.into();
    }
}

/// Stops the spinner and clears its line.
pub fn stop() {
    let spin = SPIN.lock().ok().and_then(|mut s| s.take());
    if let Some(s) = spin {
        s.stop.store(true, Ordering::Relaxed);
        let _ = s.thread.join();
    }
}

/// A message on stderr that the spinner does not draw over.
pub fn note(msg: &str) {
    let _g = OUT.lock();
    let mut e = std::io::stderr().lock();
    // The spinner may still be on the line, even while it stops.
    let clear = if std::io::stderr().is_terminal() {
        "\r\x1b[2K"
    } else {
        ""
    };
    let _ = writeln!(e, "{clear}{msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain() -> Style {
        Style {
            unicode: true,
            ..Style::default()
        }
    }

    #[test]
    fn every_line_of_the_frame_has_the_same_width() {
        let mut f = Frame::new(plain());
        f.boxed(vec!["input".into(), "target".into()]);
        f.blank();
        f.section("Availability", "1 of 2 available");
        f.line("x".repeat(200));
        f.para("! ", &"word ".repeat(60));
        let text = f.render("esc-preflight test");
        for l in text.lines() {
            assert_eq!(width(l), MAX_WIDTH, "{l}");
        }
        assert!(text.contains("├─ Availability "), "{text}");
        let ascii = Frame::new(Style::default()).render("t");
        assert!(ascii.is_ascii());
    }

    #[test]
    fn fit_keeps_escape_sequences_and_closes_them() {
        let s = "\x1b[1mabcdef\x1b[0m";
        assert_eq!(width(s), 6);
        assert_eq!(fit(s, 4, "~"), "\x1b[1mabc~\x1b[0m");
        assert_eq!(fit("abc", 4, "~"), "abc");
    }

    #[test]
    fn short_ids_drop_the_stack_and_the_leaf() {
        assert_eq!(
            short_id("S/ConfigRepoA0A331A1", Some("S/ConfigRepo/Resource")),
            "ConfigRepo"
        );
        assert_eq!(
            short_id(
                "X",
                Some("S/DataspaceConnector/Connector-example/EdcDdb/Table/Resource")
            ),
            "Connector-example/EdcDdb/Table"
        );
        assert_eq!(short_id("Fn", None), "Fn");
        assert_eq!(short_id("Globals/Function", None), "Globals/Function");
        assert_eq!(short_id("App/Outputs/Url", None), "Outputs/Url");
        assert_eq!(
            short_id("module.net.aws_subnet.a", None),
            "module.net.aws_subnet.a"
        );
    }

    #[test]
    fn elapsed_reads_in_seconds_then_minutes() {
        assert_eq!(elapsed(Duration::from_millis(3140)), "3.1s");
        assert_eq!(elapsed(Duration::from_secs(125)), "2m 05s");
    }
}
