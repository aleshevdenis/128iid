A bitsight finding (on an asset): 

```
{
  "temporary_id": "A9Jq47BBjebf1f1da4b417ba0b673d44a8cea35f7b",
  "affects_rating": false,
  "assets": [
    {
      "asset": "bitsighttechnologies.co",
      "category": "critical",
      "importance": 0.33333334,
      "is_ip": false
    }
  ],
  "details": {
    "diligence_annotations": {
      "dnskeys": [

      ],
      "rrsigs": [

      ],
      "security outcome": "Provably Insecure",
      "nsecs": [
        {
          "recordHash": "tj9tgngk3ost36nd68accje4e0a4v3jq",
          "recordType": "NSEC3",
          "algorithm": "SHA1",
          "flags": "Opt-out",
          "iterations": 1,
          "nextHash": "tjg0a1d07uhhf0ofso84v5g9vr5i8thq",
          "prevHash": "tj5hqao12o36okt4av4bd4gsce0nc79i",
          "salt": "F873A2F5",
          "types": "NS DS RRSIG"
        }
      ],
      "reason": "{{bitsighttechnologies.co./DNSKEY}} does not have a validated chain of trust",
      "message": "DNSSEC is not configured on this domain",
      "dses": [

      ]
    },
    "grade": "NEUTRAL",
    "remediations": [
      {
        "help_text": "This domain is missing a DNSKEY record and therefore cannot be authenticated using DNSSEC.",
        "message": "DNSSEC is not configured on this domain",
        "remediation_tip": "You will need to set up DNSSEC for your domain, including generating necessary keys and updating DNS zone records accordingly. See this <a target=\"new\" href=\"https://www.digitalocean.com/community/tutorials/how-to-setup-dnssec-on-an-authoritative-bind-dns-server--2\">DigitalOcean guide</a> for instructions which may be applicable to your server configuration, as well as <a target=\"new\" href=\"http://www.dnssec.net/practical-documents\">dnssec.net</a> for practical documents related to DNSSEC setup."
      }
    ],
    "sample_timestamp": "2019-01-07T08:57:40Z",
    "vulnerabilities": [

    ],
    "rollup_end_date": "2019-01-07",
    "rollup_start_date": "2018-11-12"
  },
  "evidence_key": "bitsighttechnologies.co",
  "first_seen": "2018-11-12",
  "last_seen": "2019-01-07",
  "risk_category": "Diligence",
  "risk_vector": "dnssec",
  "risk_vector_label": "DNSSEC",
  "rolledup_observation_id": "b4V74CUZ7SU_MSXZvcJe8w==",
  "severity": 1.0,
  "severity_category": "minor",
  "tags": [

  ]
}
```
