use std::borrow::Cow;
use std::ffi::{OsStr};
use std::process::Command;

pub fn preview_command(cmd: &Command) -> String {
	#[cfg(unix)]
	{
		let mut parts: Vec<String> = Vec::new();

		for (k, vopt) in cmd.get_envs() {
			match vopt {
				Some(v) => parts.push(format!(
					"{}={}",
					sh_escape(k),
					sh_escape(v),
				)),
				None => parts.push(format!("unset {}", sh_escape(k))), // env removed
			}
		}

		parts.push(sh_escape(cmd.get_program()).into_owned());
		parts.extend(cmd.get_args().map(|a| sh_escape(a).into_owned()));
		parts.join(" ")
	}

	#[cfg(windows)]
	{
		let mut parts: Vec<String> = Vec::new();

		// On Windows, emulate `cmd.exe` style env setting
		// (This is for display; Command doesn’t invoke cmd.exe.)
		let mut env_bits = Vec::new();
		for (k, vopt) in cmd.get_envs() {
			match vopt {
				Some(v) => env_bits.push(format!("set {}={}", ps_quote(k), ps_quote(v))),
				None => env_bits.push(format!("set {}=", ps_quote(k))), // unset
			}
		}
		if !env_bits.is_empty() {
			parts.push(env_bits.join(" && "));
			parts.push("&&".to_owned());
		}

		// Program + args (quote per CreateProcess rules)
		parts.push(win_quote(cmd.get_program()));
		parts.extend(cmd.get_args().map(win_quote));
		parts.join(" ")
	}
}

#[cfg(unix)]
fn sh_escape(s: &OsStr) -> Cow<'_, str> {
	let s = s.to_string_lossy();
	if s.is_empty() || s.chars().any(|c| c.is_whitespace() || "!\"#$&'()*;<>?`\\|[]{}".contains(c))
	{
		let mut out = String::from("'");
		for ch in s.chars() {
			if ch == '\'' {
				out.push_str("'\\''");
			} else {
				out.push(ch);
			}
		}
		out.push('\'');
		Cow::Owned(out)
	} else {
		Cow::Owned(s.into_owned())
	}
}

#[cfg(windows)]
fn win_quote(s: &OsStr) -> String {
	// Quote per Windows argv rules (CreateProcess / CommandLineToArgvW).
	// Wrap in "..." and escape internal " with backslashes.
	let s = s.to_string_lossy();
	if !s.contains([' ', '\t', '"', '\\']) {
		return s.into_owned();
	}
	let mut out = String::from("\"");
	let mut backslashes = 0;
	for ch in s.chars() {
		match ch {
			'\\' => backslashes += 1,
			'"' => {
				out.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
				out.push('"');
				backslashes = 0;
			}
			_ => {
				out.extend(std::iter::repeat('\\').take(backslashes));
				backslashes = 0;
				out.push(ch);
			}
		}
	}
	out.extend(std::iter::repeat('\\').take(backslashes));
	out.push('"');
	out
}

// For displaying env names/values in the "set name=value" bits.
// Single-quote for PowerShell-like readability; fine for display purposes.
#[cfg(windows)]
fn ps_quote(s: &OsStr) -> String {
	let s = s.to_string_lossy();
	if s.chars().any(|c| c.is_whitespace() || r#"'&|<>()^"%!;"#.contains(c)) {
		format!("'{}'", s.replace('\'', "''"))
	} else {
		s.into_owned()
	}
}
