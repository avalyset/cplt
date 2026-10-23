//! The `graphql-read-only` argument check (design 6.2).

#[derive(Debug, PartialEq)]
pub(crate) enum Tok {
    Name(String),
    Punct(char),
    /// A string, number or `...`: never a definition keyword.
    Other,
}

pub(crate) fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let cs: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        match c {
            ' ' | '\t' | '\n' | '\r' | ',' | '\u{feff}' => i += 1,
            '#' => {
                while i < cs.len() && cs[i] != '\n' && cs[i] != '\r' {
                    i += 1;
                }
            }
            '"' if cs.get(i + 1) == Some(&'"') && cs.get(i + 2) == Some(&'"') => {
                i += 3;
                loop {
                    match cs.get(i) {
                        None => return Err("unterminated block string".into()),
                        Some('\\') if cs[i..].starts_with(&['\\', '"', '"', '"']) => i += 4,
                        Some('"') if cs[i..].starts_with(&['"', '"', '"']) => {
                            i += 3;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
                out.push(Tok::Other);
            }
            '"' => {
                i += 1;
                loop {
                    match cs.get(i) {
                        None | Some('\n' | '\r') => return Err("unterminated string".into()),
                        Some('\\') => i += 2,
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
                out.push(Tok::Other);
            }
            '.' if cs[i..].starts_with(&['.', '.', '.']) => {
                i += 3;
                out.push(Tok::Other);
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < cs.len() && (cs[i].is_ascii_alphanumeric() || cs[i] == '_') {
                    i += 1;
                }
                out.push(Tok::Name(cs[start..i].iter().collect()));
            }
            c if c.is_ascii_digit() || c == '-' => {
                i += 1;
                while i < cs.len() && (cs[i].is_ascii_alphanumeric() || ".+-".contains(cs[i])) {
                    i += 1;
                }
                out.push(Tok::Other);
            }
            '!' | '$' | '&' | '(' | ')' | '[' | ']' | '{' | '}' | ':' | '=' | '@' | '|' => {
                i += 1;
                out.push(Tok::Punct(c));
            }
            _ => return Err(format!("unexpected character {c:?}")),
        }
    }
    Ok(out)
}

/// Skip from a definition's start to just past its selection set. Braces
/// inside parentheses (object values in variable defaults or directive
/// arguments) are counted but do not open the selection set.
pub(crate) fn skip_definition(toks: &[Tok], mut i: usize) -> Result<usize, String> {
    let mut parens = 0usize;
    let mut braces = 0usize;
    let mut opened = false;
    while let Some(t) = toks.get(i) {
        i += 1;
        match t {
            Tok::Punct('(') => parens += 1,
            Tok::Punct(')') => parens = parens.checked_sub(1).ok_or("unbalanced )")?,
            Tok::Punct('{') => {
                if parens == 0 {
                    opened = true;
                }
                braces += 1;
            }
            Tok::Punct('}') => {
                braces = braces.checked_sub(1).ok_or("unbalanced }")?;
                if opened && braces == 0 && parens == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
    }
    Err("unterminated definition".into())
}

/// The broker's `graphql-read-only` check (design 6.2): every definition in
/// the document, fragments included, must be a query or a fragment, with
/// exactly one operation. Anything it cannot read is refused.
pub fn graphql_read_only(doc: &str) -> Result<(), String> {
    let toks = lex(doc)?;
    let mut ops = 0;
    let mut i = 0;
    while let Some(t) = toks.get(i) {
        match t {
            Tok::Punct('{') => ops += 1,
            Tok::Name(n) if n == "query" => ops += 1,
            Tok::Name(n) if n == "fragment" => {}
            Tok::Name(n) if n == "mutation" || n == "subscription" => {
                return Err(format!("{n} operations are not allowed; only query"));
            }
            _ => return Err("not an executable GraphQL document".into()),
        }
        i = skip_definition(&toks, i)?;
    }
    match ops {
        1 => Ok(()),
        0 => Err("no operation in the document".into()),
        n => Err(format!("{n} operations in one document; send one query")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphql_checker() {
        for ok in [
            "{ me { name } }",
            "query Q($a: In = {x: 1}) @d(v: {y: 2}) { a(b: \"mutation {\") { ...F } }\nfragment F on T { c }",
            "# mutation\nquery mutation { mutation }",
            "query { a(s: \"\"\"block \\\"\"\" mutation\"\"\") }",
        ] {
            assert_eq!(graphql_read_only(ok), Ok(()), "{ok}");
        }
        for bad in [
            "mutation { delete }",
            "subscription { s }",
            "query A { a } query B { b }",
            "{ a } mutation M { m }",
            "fragment F on T { a }",
            "fragment F on T { a } mutation { m }",
            "query { a ",
            "query { a(s: \"x) }",
            "type Query { a: Int }",
            "query { a } }",
            "",
            "query { a ^ }",
        ] {
            assert!(graphql_read_only(bad).is_err(), "{bad}");
        }
    }
}
