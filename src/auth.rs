//! Authentication and client identification utilities
//!
//! Provides secure IP address extraction with trusted proxy support
//! to prevent IP spoofing attacks.

use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::IpAddr;

/// Extracts client IP address from headers with trusted proxy validation.
///
/// # Algorithm
/// 1. If trusted_proxies is empty, trust X-Real-Ip header directly
/// 2. Otherwise, parse X-Forwarded-For from right to left
/// 3. Skip all IPs that belong to trusted_proxies (rightmost = closest proxy)
/// 4. First non-trusted IP is the real client
/// 5. Fallback to X-Real-Ip if X-Forwarded-For is empty/invalid
///
/// # Security
/// This prevents IP spoofing where an attacker sets X-Forwarded-For
/// to fake their IP address. Only IPs from trusted proxies are considered.
pub fn extract_client_ip(headers: &HeaderMap, trusted_proxies: &[IpNet]) -> Option<String> {
    // If no trusted proxies configured, simply use X-Real-Ip
    // This assumes a single trusted proxy or direct connection
    if trusted_proxies.is_empty() {
        return headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());
    }

    // Try X-Forwarded-For first (standard for proxy chains)
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        // X-Forwarded-For: client, proxy1, proxy2 (left to right)
        // We parse from right to left to find the first untrusted IP
        let ips: Vec<&str> = forwarded.split(',').map(|s| s.trim()).collect();
        
        for ip_str in ips.iter().rev() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                // Check if this IP is from a trusted proxy
                let is_trusted = trusted_proxies.iter().any(|net| net.contains(&ip));
                
                if !is_trusted {
                    // Found the first non-trusted IP (the real client)
                    return Some(ip.to_string());
                }
                // Continue to next IP (more towards the client)
            }
        }
        
        // If all IPs are trusted, the leftmost one is the client
        // (this shouldn't happen in normal scenarios)
        if let Some(first_ip) = ips.first() {
            return Some(first_ip.to_string());
        }
    }

    // Fallback to X-Real-Ip (only if no X-Forwarded-For)
    // This header should only be set by trusted proxies
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn create_headers_with_forwarded(forwarded: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_str(forwarded).unwrap());
        headers
    }

    fn create_headers_with_real_ip(real_ip: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_str(real_ip).unwrap());
        headers
    }

    #[test]
    fn test_empty_trusted_proxies_uses_x_real_ip() {
        let headers = create_headers_with_real_ip("1.2.3.4");
        let result = extract_client_ip(&headers, &[]);
        assert_eq!(result, Some("1.2.3.4".to_string()));
    }

    #[test]
    fn test_extracts_client_from_forwarded() {
        let headers = create_headers_with_forwarded("1.2.3.4, 10.0.0.1, 10.0.0.2");
        let trusted: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
        ];
        let result = extract_client_ip(&headers, &trusted);
        assert_eq!(result, Some("1.2.3.4".to_string()));
    }

    #[test]
    fn test_skips_all_trusted_proxies() {
        let headers = create_headers_with_forwarded("192.168.1.1, 10.0.0.1, 172.16.0.1");
        let trusted: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
        ];
        let result = extract_client_ip(&headers, &trusted);
        assert_eq!(result, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_no_forwarded_uses_real_ip() {
        let headers = create_headers_with_real_ip("5.6.7.8");
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let result = extract_client_ip(&headers, &trusted);
        assert_eq!(result, Some("5.6.7.8".to_string()));
    }

    #[test]
    fn test_prevents_spoofing() {
        // Attacker tries to spoof by adding fake IP at the end
        // (closest to server - rightmost position)
        let headers = create_headers_with_forwarded("1.2.3.4, 10.0.0.1, 9.9.9.9");
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let result = extract_client_ip(&headers, &trusted);
        // 9.9.9.9 is NOT trusted, so it should be returned
        // (representing an untrusted proxy or attacker)
        assert_eq!(result, Some("9.9.9.9".to_string()));
    }

    #[test]
    fn test_no_headers_returns_none() {
        let headers = HeaderMap::new();
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let result = extract_client_ip(&headers, &trusted);
        assert_eq!(result, None);
    }
}
