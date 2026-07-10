# 1-6 Input Size and Integrity Validation

This module embeds the ARGUS W16 engine under `engine/` and converts its JSON
artifacts into the common ARGUS `SectionReport` format.

## Module Layout

- `module.py`: diagnosis registry entry.
- `manifest.yaml`: catalog metadata.
- `scanner.py`: orchestration for one 1-6 scan.
- `g16_targets.py`: target URL and embedded engine path resolution.
- `g16_auth.py`: test account selection and command redaction.
- `g16_payloads.py`: payload source metadata.
- `g16_probes.py`: embedded W16 process runner.
- `g16_classification.py`: raw finding to ARGUS finding conversion.
- `engine/`: copied W16 scanner implementation, including `core/`,
  `parsers/`, and `payloads/`.

## Output

The embedded engine writes its raw artifacts below:

`data/evidence/1-6/w16/W16_<run_id>/`

The module writes the normalized ARGUS report to:

`data/report/1-6/latest.yaml`
