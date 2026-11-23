import { describe, expect, it } from 'vitest';
import { hostOfWebsite, isIpAddress, registrableDomain, setPublicSuffixRules } from './psl';

describe('registrableDomain', () => {
  it('gives the domain a site owns, not its subdomains', () => {
    expect(registrableDomain('accounts.example.com')).toBe('example.com');
    expect(registrableDomain('Mail.Example.COM.')).toBe('example.com');
    expect(registrableDomain('example.com')).toBe('example.com');
  });

  it('honours multi-label suffixes', () => {
    expect(registrableDomain('www.bbc.co.uk')).toBe('bbc.co.uk');
    expect(registrableDomain('shop.example.com.au')).toBe('example.com.au');
  });

  it('keeps two sites under a shared host apart', () => {
    expect(registrableDomain('alice.herokuapp.com')).toBe('alice.herokuapp.com');
    expect(registrableDomain('bob.herokuapp.com')).toBe('bob.herokuapp.com');
    expect(registrableDomain('www.alice.github.io')).toBe('alice.github.io');
  });

  it('follows wildcard and exception rules', () => {
    expect(registrableDomain('a.b.ck')).toBe('a.b.ck');
    expect(registrableDomain('www.ck')).toBe('www.ck');
    expect(registrableDomain('x.www.ck')).toBe('www.ck');
  });

  it('returns an IP address or a lone label whole', () => {
    expect(registrableDomain('192.0.2.10')).toBe('192.0.2.10');
    expect(registrableDomain('localhost')).toBe('localhost');
    expect(isIpAddress('2001:db8::1')).toBe(true);
    expect(isIpAddress('example.com')).toBe(false);
  });

  it('converts a host in another script to Punycode', () => {
    expect(registrableDomain('www.bücher.example')).toBe('xn--bcher-kva.example');
  });

  it('takes a full snapshot when one is given', () => {
    setPublicSuffixRules('com\nexample.com\n');
    expect(registrableDomain('a.b.example.com')).toBe('b.example.com');
    // Back to the bundled rules for the other tests.
    setPublicSuffixRules('co.uk\n');
    expect(registrableDomain('www.bbc.co.uk')).toBe('bbc.co.uk');
  });
});

describe('hostOfWebsite', () => {
  it('drops the scheme, path, port and user info', () => {
    expect(hostOfWebsite('https://user:pw@Example.com:8443/login?x=1#top')).toBe('example.com');
    expect(hostOfWebsite('example.co')).toBe('example.co');
    expect(hostOfWebsite('  https://www.example.co/a ')).toBe('www.example.co');
  });

  it('reads an IPv6 literal', () => {
    expect(hostOfWebsite('http://[2001:db8::1]:8080/x')).toBe('2001:db8::1');
  });
});
