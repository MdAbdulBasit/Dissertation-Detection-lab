# Sigma rules

Detection-as-code artefacts. One `.yml` per technique, authored in Sigma first, then translated to a
Wazuh local rule in `/var/ossec/etc/rules/local_rules.xml` on Blue.

**Naming:** `<TECHNIQUE_ID>_<short_description>.yml`

**Why Sigma first:** the dissertation claims detection engineering as a portable, reviewable practice.
A Wazuh XML rule is platform-specific; the Sigma rule is the vendor-neutral artefact that demonstrates
the engineering discipline, and it is what makes the work reproducible on a different SIEM. Writing
Wazuh XML directly skips the contribution.

Each file must carry the corresponding Wazuh rule ID in a deployment note, and that ID must match
`RULE_ID_REGISTER.md`.
