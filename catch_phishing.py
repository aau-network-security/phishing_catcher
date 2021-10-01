#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import csv
import re
import math

import cryptography
from tqdm import tqdm
import yaml
import time
import os
import sys
from Levenshtein import distance
from cryptography.hazmat.backends import default_backend
from termcolor import colored, cprint
from tld import get_tld
from os import listdir
from cryptography import x509

from confusables import unconfuse

certstream_url = 'wss://certstream.calidog.io'

log_suspicious = os.path.dirname(os.path.realpath(__file__)) + '/suspicious_domains_' + time.strftime(
    "%Y-%m-%d") + '.log'

suspicious_yaml = os.path.dirname(os.path.realpath(__file__)) + '/suspicious.yaml'

external_yaml = os.path.dirname(os.path.realpath(__file__)) + '/external.yaml'

def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for t in suspicious['tlds']:
        if domain.endswith(t):
            score += 20

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]

    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        pass

    # Higer entropy is kind of suspicious
    score += int(round(entropy(domain) * 10))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split("\W+", domain)

    # ie. detect fake .com (ie. *.com-account-management.info)
    if words_in_domain[0] in ['com', 'net', 'org']:
        score += 10

    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k, s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score


def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar.update(1)
            score = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" == message['data']['leaf_cert']['issuer']['O']:
                score += 10

            if score >= 100:
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline', 'bold']), score))
            elif score >= 90:
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline']), score))
            elif score >= 80:
                tqdm.tqdm.write(
                    "[!] Likely    : "
                    "{} (score={})".format(colored(domain, 'yellow', attrs=['underline']), score))
            elif score >= 65:
                tqdm.tqdm.write(
                    "[+] Potential : "
                    "{} (score={})".format(colored(domain, attrs=['underline']), score))

            if score >= 75:
                with open(log_suspicious, 'a') as f:
                    f.write("{}\n".format(domain))


def scores_from_cert(cert):
    scores = []
    for san in domains_from_cert(cert):
        score = score_domain(san)
        scores.append(score)
    return scores


def domains_from_cert(cert):
    domains = []

    # SANs
    try:
        sans_ext = cert.extensions.get_extension_for_oid(cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for candidate_san in sans_ext.value:
            if type(candidate_san) == cryptography.x509.general_name.DNSName:
                san = candidate_san.value
                domains.append(san)
    except:
        pass

    # Subject
    try:
        cn_parts = cert.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)
        cn = cn_parts[0].value
    except:
        if cn not in domains:
            domains.append(cn)

    return domains


if __name__ == '__main__':
    with open(suspicious_yaml, 'r') as fname:
        suspicious = yaml.safe_load(fname)

    with open(external_yaml, 'r') as fname:
        external = yaml.safe_load(fname)

    if external['override_suspicious.yaml'] is True:
        suspicious = external
    else:
        if external['keywords'] is not None:
            suspicious['keywords'].update(external['keywords'])

        if external['tlds'] is not None:
            suspicious['tlds'].update(external['tlds'])

    # read from disk here
    if len(sys.argv) != 3:
        print(f"Usage: python catch_phishing.py <input directory> <output file>")
        exit(-1)

    input_dir = sys.argv[1]
    output_file = sys.argv[2]

    score_map = {}
    for fname in tqdm(listdir(input_dir)):
        if fname.endswith(".crt"):

            fpath = os.path.join(input_dir, fname)
            file = open(fpath, 'rb')
            cert_bytes = file.read()
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
            sans = domains_from_cert(cert)

            scores = scores_from_cert(cert)

            max_score = max(scores)
            verdict = 'benign'
            if max(scores) >= 90:
                verdict = 'suspicious'
            elif max(scores) >= 80:
                verdict = 'likely'
            elif max(scores) >= 65:
                verdict = 'potential'

            cert_id = fname[:-4]
            print(f"Max score for '{cert_id}' = {max_score}")
            score_map[cert_id] = max_score

    with open(output_file, 'w') as f:
        writer = csv.writer(f)
        for k, v in tqdm(score_map.items()):
            writer.writerow([k, v])