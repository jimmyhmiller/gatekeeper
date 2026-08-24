//! Static file serving for a route mapped to a directory.
//!
//! `rest` is the request path after the matched route prefix. It has already
//! been normalized and traversal-rejected by [`crate::route::Router::normalize`],
//! so it contains no `..` components. As belt-and-suspenders we still
//! canonicalize the final path and confirm it stays within the served root —
//! if a symlink inside the root points outside, we refuse.

use std::path::Path;

use crate::reply::Reply;

/// Serve `rest` (e.g. "/index.html" or "" ) from under `root`.
pub fn serve(root: &Path, rest: &str) -> Reply {
    // Map the request remainder onto the filesystem. `rest` starts with '/' or
    // is empty; strip the leading slash so join() treats it as relative.
    let rel = rest.trim_start_matches('/');
    let mut path = root.join(rel);

    // Directory -> index.html (simple default; no autoindex, by design).
    if path.is_dir() {
        path = path.join("index.html");
    }

    // Canonicalize and confirm containment. canonicalize() also resolves
    // symlinks, so this catches a symlink escaping the root.
    let (canon_root, canon_path) = match (root.canonicalize(), path.canonicalize()) {
        (Ok(r), Ok(p)) => (r, p),
        // A missing file fails to canonicalize -> 404 (don't leak which part).
        _ => return Reply::status(404, "Not Found"),
    };
    if !canon_path.starts_with(&canon_root) {
        // Symlink or join escaped the root. Treat as not found.
        return Reply::status(404, "Not Found");
    }

    match std::fs::read(&canon_path) {
        Ok(bytes) => {
            let ct = content_type(&canon_path);
            Reply::new(200, bytes).with_header("Content-Type", ct)
        }
        Err(_) => Reply::status(404, "Not Found"),
    }
}

/// Extension → MIME map.
///
/// Anything not listed falls back to `application/octet-stream`, which browsers
/// download rather than render. That is the safe default and often the useful
/// one for a file drop, but it is annoying when you just wanted to look at a
/// PDF or a log, hence the size of this table.
///
/// Matching is case-insensitive: real folders are full of `IMG_1234.JPG`.
///
/// Text-ish formats, including source code, are served `text/plain` so they
/// render in the browser instead of downloading. The exceptions are the few
/// that browsers genuinely understand as themselves (`html`, `svg`, `json`).
///
/// Note that `html` and `svg` are served as themselves, which means a file you
/// drop can run script **on this origin**. The session cookie is `HttpOnly` so
/// it cannot be read, but such a script could still make authenticated requests
/// as you. That is fine for files you authored and worth remembering before
/// using a drop folder to stash something you did not.
fn content_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        // Web
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" | "cjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "jsonl" | "ndjson" => "application/x-ndjson",
        "map" => "application/json",
        "wasm" => "application/wasm",
        "xml" | "xsl" | "xsd" => "application/xml",
        "rss" | "atom" => "application/xml",

        // Images
        "png" => "image/png",
        "jpg" | "jpeg" | "jpe" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" | "svgz" => "image/svg+xml",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "tif" | "tiff" => "image/tiff",
        "avif" => "image/avif",
        "heic" | "heif" => "image/heic",
        "jxl" => "image/jxl",
        "psd" => "image/vnd.adobe.photoshop",

        // Audio
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "mid" | "midi" => "audio/midi",
        "aiff" | "aif" => "audio/aiff",

        // Video
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "avi" => "video/x-msvideo",
        "mpeg" | "mpg" => "video/mpeg",
        "ogv" => "video/ogg",

        // Documents
        "pdf" => "application/pdf",
        "epub" => "application/epub+zip",
        "rtf" => "application/rtf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "odp" => "application/vnd.oasis.opendocument.presentation",

        // Archives and images-of-disks
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" | "tgz" => "application/gzip",
        "bz2" => "application/x-bzip2",
        "xz" => "application/x-xz",
        "zst" => "application/zstd",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "iso" => "application/x-iso9660-image",
        "dmg" => "application/x-apple-diskimage",
        "deb" => "application/vnd.debian.binary-package",
        "rpm" => "application/x-rpm",

        // Fonts
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",

        // Data and config, served as text so they open in the browser
        "csv" => "text/csv; charset=utf-8",
        "tsv" => "text/tab-separated-values; charset=utf-8",
        "ics" => "text/calendar; charset=utf-8",
        "vcf" => "text/vcard; charset=utf-8",

        // Everything else that is really just text. Deliberately `text/plain`
        // rather than a precise `text/x-rust`-style type, because the point is
        // that it renders when you click it.
        "txt" | "md" | "markdown" | "log" | "text" | "me" | "nfo" => "text/plain; charset=utf-8",
        "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "properties" | "env" => {
            "text/plain; charset=utf-8"
        }
        "rs" | "go" | "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" => "text/plain; charset=utf-8",
        "py" | "rb" | "pl" | "php" | "lua" | "tcl" | "r" => "text/plain; charset=utf-8",
        "java" | "kt" | "kts" | "scala" | "groovy" | "cs" | "fs" | "vb" => {
            "text/plain; charset=utf-8"
        }
        "ts" | "tsx" | "jsx" | "vue" | "svelte" => "text/plain; charset=utf-8",
        "swift" | "m" | "mm" | "zig" | "nim" | "v" | "d" => "text/plain; charset=utf-8",
        "hs" | "ml" | "mli" | "ex" | "exs" | "erl" | "hrl" | "elm" | "purs" => {
            "text/plain; charset=utf-8"
        }
        "clj" | "cljs" | "cljc" | "edn" | "lisp" | "lsp" | "scm" | "rkt" | "el" | "coil" => {
            "text/plain; charset=utf-8"
        }
        "sh" | "bash" | "zsh" | "fish" | "ps1" | "bat" | "cmd" => "text/plain; charset=utf-8",
        "sql" | "graphql" | "gql" | "proto" | "thrift" | "avsc" => "text/plain; charset=utf-8",
        "diff" | "patch" | "asm" | "s" | "ll" | "wat" => "text/plain; charset=utf-8",
        "dockerfile" | "makefile" | "mk" | "cmake" | "gradle" | "bazel" | "bzl" => {
            "text/plain; charset=utf-8"
        }

        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ct(name: &str) -> &'static str {
        content_type(&PathBuf::from(name))
    }

    #[test]
    fn common_types_are_mapped() {
        assert_eq!(ct("a.pdf"), "application/pdf");
        assert_eq!(ct("a.png"), "image/png");
        assert_eq!(ct("a.mp4"), "video/mp4");
        assert_eq!(ct("a.zip"), "application/zip");
        assert_eq!(ct("a.json"), "application/json");
        assert_eq!(ct("a.html"), "text/html; charset=utf-8");
    }

    #[test]
    fn matching_is_case_insensitive() {
        // A camera roll is full of these; before this they all downloaded as
        // application/octet-stream.
        assert_eq!(ct("IMG_1234.JPG"), "image/jpeg");
        assert_eq!(ct("SCAN.PDF"), "application/pdf");
        assert_eq!(ct("Notes.MD"), "text/plain; charset=utf-8");
    }

    #[test]
    fn source_and_config_render_as_text() {
        for f in ["a.rs", "a.py", "a.toml", "a.yaml", "a.sql", "a.clj", "a.sh", "a.log"] {
            assert_eq!(ct(f), "text/plain; charset=utf-8", "{f} should render, not download");
        }
    }

    #[test]
    fn unknown_and_extensionless_fall_back_to_download() {
        assert_eq!(ct("a.wat-is-this"), "application/octet-stream");
        assert_eq!(ct("LICENSE"), "application/octet-stream");
        assert_eq!(ct("archive.tar.gz"), "application/gzip", "compound: last extension wins");
    }
}
