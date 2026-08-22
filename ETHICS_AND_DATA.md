# Ethics and data handling

## Scope

The prototype measures browser rendering behavior. Such measurements can become
device-identifying, and the original collection records include direct and
indirect identifiers. They therefore require stricter handling than ordinary
application logs.

## Restricted source records

The local `users/` directory is the source collection used to derive the paper's
aggregate results. Its records include categories such as IP addresses, full
user-agent strings, timestamps, rendering hashes, and raw Canvas-derived data.
The directory is retained locally for provenance but is:

- excluded from Git export archives, Docker build contexts, and the artifact ZIP;
- never required by evaluator instructions or automated tests;
- never modified by the public-dataset generation script;
- unsuitable for a public Git hosting history without a separate, reviewed
  history-cleaning and re-consent process.

Access should be limited to authorized researchers under the applicable consent,
institutional policy, and retention schedule. Do not upload this directory to a
public artifact service.

## Released evaluation data

`data/public/records.jsonl` is a derived dataset designed to validate paper
Tables 2 and 3 without exposing original measurements. It retains only:

- a newly assigned sequential participant ID;
- coarse operating-system and browser categories;
- modality availability, number of repeated runs, number of unique results, and
  whether the first session was stable.

It excludes original usernames, passwords, IP addresses, full user agents,
timestamps, seeds, renderer strings, raw media, and all rendering hashes. See the
schema in `data/public/README.md`.

## New data collection

Registration requires an affirmative consent checkbox and stores the consent
version and time with the local account. By default, new collection stores only
the preliminary fingerprint hash, coarse non-rendering environment fields, and
the modality results necessary for the demo. Direct client metadata and raw
fingerprints remain opt-in configuration features and should be enabled only
under an approved protocol.

## Paper consistency note

The paper states that data were anonymized and that personally identifiable or
device-identifiable information was not stored. The preserved source records
contain fields that are broader than that statement suggests. Before final
publication, the authors should reconcile the wording with the actual collection
and retention practice in the paper's ethics appendix. This repository does not
silently delete or rewrite the source evidence.
