-- +goose Up
-- Up --------------------------------------------------------------
-- Nuclei templates (https://github.com/projectdiscovery/nuclei-templates)
--
-- The presence of a Nuclei template for a CVE is a leading exploit-commodity
-- signal — every scanner now finds it. Tracking template additions runs
-- 2–6 weeks ahead of EPSS movement in practice.
--
-- The ingestor downloads the main-branch tarball, walks every .yaml file
-- under http/cves/, dns/, network/, etc., and extracts CVE references plus
-- severity/tags/authors from the template YAML.

CREATE TABLE IF NOT EXISTS nuclei_templates (
    template_id     TEXT        PRIMARY KEY,             -- yaml `id` field (typically CVE-YYYY-NNNNN)
    name            TEXT,
    severity        TEXT,                                -- info / low / medium / high / critical / unknown
    template_path   TEXT,                                -- path inside the nuclei-templates repo
    authors         TEXT[]      NOT NULL DEFAULT '{}',
    description     TEXT,
    cves            TEXT[]      NOT NULL DEFAULT '{}',   -- CVE refs from classification.cve-id + tags
    cwes            TEXT[]      NOT NULL DEFAULT '{}',
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    yaml_sha256     TEXT,                                -- SHA-256 of the YAML body, for change detection
    raw             TEXT        NOT NULL,                -- the original YAML for round-trip preservation
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE nuclei_templates IS
  'ProjectDiscovery Nuclei templates — exploit-commodity signal. When a CVE gets a template, exploitability has crossed a scanner-distribution threshold.';

CREATE INDEX IF NOT EXISTS idx_nuclei_severity      ON nuclei_templates (severity);
CREATE INDEX IF NOT EXISTS idx_nuclei_cves          ON nuclei_templates USING gin (cves);
CREATE INDEX IF NOT EXISTS idx_nuclei_cwes          ON nuclei_templates USING gin (cwes);
CREATE INDEX IF NOT EXISTS idx_nuclei_tags          ON nuclei_templates USING gin (tags);
CREATE INDEX IF NOT EXISTS idx_nuclei_first_seen    ON nuclei_templates (first_seen_at DESC);

-- +goose Down
DROP TABLE IF EXISTS nuclei_templates;
