use opentelemetry::propagation::{Extractor, Injector};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

pub struct HeaderExtractor<'a>(pub &'a HeaderMap);

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

pub struct HeaderInjector<'a>(pub &'a mut HeaderMap);

impl<'a> Injector for HeaderInjector<'a> {
    fn set(&mut self, key: &str, value: std::string::String) {
        if let Ok(header_name) = HeaderName::from_bytes(key.as_bytes())
            && let Ok(header_value) = HeaderValue::from_str(&value)
        {
            self.0.insert(header_name, header_value);
        }
    }
}
