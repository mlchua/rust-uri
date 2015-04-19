
use regex::{Captures, Regex};
use std::string::{String, ToString};

const URI_REGEX: &'static str = "^((?P<scheme>[^:/?#]+):)?(//(?P<authority>[^/?#]*))?(?P<path>[^?#]*)(\\?(?P<query>[^#]*))?(#(?P<fragment>.*))?";

struct Uri
{
    uri: String
}

pub fn is_valid_scheme(scheme: &str) -> Result<(), String>
{
    // For reference:
    //
    // scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    if !scheme.starts_with(|c: char| is_ascii_alpha(c))
    {
        return Err(format!("Scheme '{}' must start with as ASCII alpha character.", scheme))
    }

    let is_valid_scheme_token = |token: char| -> bool
    {
        return is_ascii_alpha(token) ||
               is_ascii_digit(token) ||
               token == '+' ||
               token == '-' ||
               token == '.'
    };

    if scheme.contains(|c: char| !is_valid_scheme_token(c))
    {
        return Err(format!("Scheme '{}' contains invalid token character.", scheme))
    }

    Ok(())
}

impl Uri
{
    pub fn from_str(&self, uri: &str) -> Result<Uri, String>
    {
        let captures_option = get_uri_regex().captures(uri);

        if captures_option.is_none()
        {
            return Err(format!("URI '{}' cannot be parsed into its components", uri))
        }
        let captures = captures_option.unwrap();

        let scheme = captures.name("scheme").unwrap_or("");
        if scheme != "" { try!(is_valid_scheme(scheme)); }

        Ok(Uri
        {
            uri: uri.to_string(),
        })
    }
}

///////////////////////////////////////////////////////////////////////////////
//
// Private Functions
//
///////////////////////////////////////////////////////////////////////////////

fn get_uri_regex() -> Regex
{
    // regex will not change so naively unwrap it
    return Regex::new(URI_REGEX).unwrap()
}

fn is_ascii_alpha(token: char) -> bool {
    // ALPHA       = (%41-%5A and %61-%7A)
    return (token >= 'A' && token <= 'Z') ||
           (token >= 'a' && token <= 'z')
}

fn is_ascii_digit(token: char) -> bool {
    // DIGIT       = (%30-%39)
    return token >= '0' && token <= '9'
}

///////////////////////////////////////////////////////////////////////////////
//
// Tests
//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests
{
    use regex::Regex;
    use super::is_ascii_alpha;
    use super::is_ascii_digit;
    use super::get_uri_regex;

    const FTP_URI:    &'static str = "ftp://ftp.is.co.za/rfc/rfc1808.txt";
    const HTTP_URI:   &'static str = "http://www.ietf.org:80/rfc/rfc2396.txt";
    const LDAP_URI:   &'static str = "ldap://[2001:db8::7]/c=GB?objectClass?one";
    const MAILTO_URI: &'static str = "mailto:John.Doe@example.com";
    const NEWS_URI:   &'static str = "news:comp.infosystems.www.servers.unix";
    const TEL_URI:    &'static str = "tel:+1-816-555-1212";
    const TELNET_URI: &'static str = "telnet://192.0.2.16:80/";
    const URN_URI:    &'static str = "urn:oasis:names:specification:docbook:dtd:xml:4.1.2";

    #[test]
    fn assert_uri_regex_matches_for_ftp_protocol()
    {
        // ftp://ftp.is.co.za/rfc/rfc1808.txt
        let caps = get_uri_regex().captures(FTP_URI).unwrap();
        assert_eq!(caps.name("scheme"), Some("ftp"));
        assert_eq!(caps.name("authority"), Some("ftp.is.co.za"));
        assert_eq!(caps.name("path"), Some("/rfc/rfc1808.txt"));
        assert_eq!(caps.name("query"), None);
        assert_eq!(caps.name("fragment"), None);
    }

    #[test]
    fn assert_uri_regex_matches_for_http_protocol()
    {
        // http://www.ietf.org/rfc/rfc2396.txt
        let caps = get_uri_regex().captures(HTTP_URI).unwrap();
        assert_eq!(caps.name("scheme"), Some("http"));
        assert_eq!(caps.name("authority"), Some("www.ietf.org:80"));
        assert_eq!(caps.name("path"), Some("/rfc/rfc2396.txt"));
        assert_eq!(caps.name("query"), None);
        assert_eq!(caps.name("fragment"), None);
    }

    #[test]
    fn assert_uri_regex_matches_for_ldap_protocol()
    {
        // ldap://[2001:db8::7]/c=GB?objectClass?one
        let caps = get_uri_regex().captures(LDAP_URI).unwrap();
        assert_eq!(caps.name("scheme"), Some("ldap"));
        assert_eq!(caps.name("authority"), Some("[2001:db8::7]"));
        assert_eq!(caps.name("path"), Some("/c=GB"));
        assert_eq!(caps.name("query"), Some("objectClass?one"));
        assert_eq!(caps.name("fragment"), None);
    }

    #[test]
    fn assert_uri_regex_matches_for_mailto_protocol()
    {
        // mailto:John.Doe@example.com
        let caps = get_uri_regex().captures(MAILTO_URI).unwrap();
        assert_eq!(caps.name("scheme"), Some("mailto"));
        assert_eq!(caps.name("authority"), None);
        assert_eq!(caps.name("path"), Some("John.Doe@example.com"));
        assert_eq!(caps.name("query"), None);
        assert_eq!(caps.name("fragment"), None);
    }

    #[test]
    fn assert_uri_regex_matches_for_news_protocol()
    {
        // news:comp.infosystems.www.servers.unix
        let caps = get_uri_regex().captures(NEWS_URI).unwrap();
        assert_eq!(caps.name("scheme"), Some("news"));
        assert_eq!(caps.name("authority"), None);
        assert_eq!(caps.name("path"), Some("comp.infosystems.www.servers.unix"));
        assert_eq!(caps.name("query"), None);
        assert_eq!(caps.name("fragment"), None);
    }

    #[test]
    fn assert_uri_regex_matches_for_tel_protocol()
    {
        // tel:+1-816-555-1212
        let caps = get_uri_regex().captures(TEL_URI).unwrap();
        assert_eq!(caps.name("scheme"), Some("tel"));
        assert_eq!(caps.name("authority"), None);
        assert_eq!(caps.name("path"), Some("+1-816-555-1212"));
        assert_eq!(caps.name("query"), None);
        assert_eq!(caps.name("fragment"), None);
    }

    #[test]
    fn assert_uri_regex_matches_for_telnet_protocol()
    {
        // telnet://192.0.2.16:80/
        let caps = get_uri_regex().captures(TELNET_URI).unwrap();
        assert_eq!(caps.name("scheme"), Some("telnet"));
        assert_eq!(caps.name("authority"), Some("192.0.2.16:80"));
        assert_eq!(caps.name("path"), Some("/"));
        assert_eq!(caps.name("query"), None);
        assert_eq!(caps.name("fragment"), None);
    }

    #[test]
    fn assert_uri_regex_matches_for_urn_protocol()
    {
        // urn:oasis:names:specification:docbook:dtd:xml:4.1.2
        let caps = get_uri_regex().captures(URN_URI).unwrap();
        assert_eq!(caps.name("scheme"), Some("urn"));
        assert_eq!(caps.name("authority"), None);
        assert_eq!(caps.name("path"), Some("oasis:names:specification:docbook:dtd:xml:4.1.2"));
        assert_eq!(caps.name("query"), None);
        assert_eq!(caps.name("fragment"), None);
    }

    #[test]
    fn is_ascii_alpha_lowercase_is_true()
    {
        for token in "abcdefhijklmnopqrstuvwxyz".chars()
        {
            assert_eq!(is_ascii_alpha(token), true);
        }
    }

    #[test]
    fn is_ascii_alpha_uppercase_is_true()
    {
        for token in "ABCDEFHIJKLMNOPQRSTUVWXYZ".chars()
        {
            assert_eq!(is_ascii_alpha(token), true);
        }
    }

    #[test]
    fn is_ascii_alpha_digits_is_false()
    {
        for token in "0123456789!#$".chars()
        {
            assert_eq!(is_ascii_alpha(token), false);
        }
    }

    #[test]
    fn is_ascii_alpha_valid_alpha_unicode_is_false()
    {
        for token in "äê".chars()
        {
            assert_eq!(token.is_alphabetic(), true);
            assert_eq!(is_ascii_alpha(token), false);
        }
    }

    #[test]
    fn is_ascii_digit_correct_is_true()
    {
        for token in "0123456789".chars()
        {
            assert_eq!(is_ascii_digit(token), true);
        }
    }

    #[test]
    fn is_ascii_digit_valid_digit_unicode_is_false()
    {
        for token in "０１２".chars()
        {
            assert_eq!(token.is_numeric(), true);
            assert_eq!(is_ascii_digit(token), false);
        }
    }
}
