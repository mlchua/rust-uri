
use regex::Regex;

const URI_REGEX: &'static str = "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?";

struct Uri
{
    uri: String
}

fn get_uri_regex() -> Regex
{
    // regex will not change so naively unwrap it
    return Regex::new(URI_REGEX).unwrap()
}

impl Uri
{

}

#[cfg(test)]
mod tests
{
    use regex::Regex;
    use super::get_uri_regex;

    const FTP_URI:    &'static str = "ftp://ftp.is.co.za/rfc/rfc1808.txt";
    const HTTP_URI:   &'static str = "http://www.ietf.org/rfc/rfc2396.txt";
    const LDAP_URI:   &'static str = "ldap://[2001:db8::7]/c=GB?objectClass?one";
    const MAILTO_URI: &'static str = "ldap://[2001:db8::7]/c=GB?objectClass?one";
    const NEWS_URI:   &'static str = "news:comp.infosystems.www.servers.unix";
    const TEL_URI:    &'static str = "tel:+1-816-555-1212";
    const TELNET_URI: &'static str = "telnet://192.0.2.16:80/";
    const URN_URI:    &'static str = "urn:oasis:names:specification:docbook:dtd:xml:4.1.2";

    #[test]
    fn assert_uri_regex_matches_for_ftp_protocol()
    {
        assert_eq!(get_uri_regex().is_match(FTP_URI), true);
    }

    #[test]
    fn assert_uri_regex_matches_for_http_protocol()
    {
        assert_eq!(get_uri_regex().is_match(HTTP_URI), true);
    }

    #[test]
    fn assert_uri_regex_matches_for_ldap_protocol()
    {
        assert_eq!(get_uri_regex().is_match(LDAP_URI), true);
    }

    #[test]
    fn assert_uri_regex_matches_for_mailto_protocol()
    {
        assert_eq!(get_uri_regex().is_match(MAILTO_URI), true);
    }

    #[test]
    fn assert_uri_regex_matches_for_news_protocol()
    {
        assert_eq!(get_uri_regex().is_match(NEWS_URI), true);
    }

    #[test]
    fn assert_uri_regex_matches_for_tel_protocol()
    {
        assert_eq!(get_uri_regex().is_match(TEL_URI), true);
    }

    #[test]
    fn assert_uri_regex_matches_for_telnet_protocol()
    {
        assert_eq!(get_uri_regex().is_match(TELNET_URI), true);
    }

    #[test]
    fn assert_uri_regex_matches_for_urn_protocol()
    {
        assert_eq!(get_uri_regex().is_match(URN_URI), true);
    }
}
