# DomainDig v3.0.0 Architecture

## Overview

DomainDig is a local-first inspection platform built around one canonical output model: `DomainReport`.

Inspection flow:

1. `DomainInspectionService.inspect(domain:)` gathers live and cached section data into `LookupSnapshot`.
2. `DomainReportBuilder` converts the snapshot into a canonical `DomainReport`.
3. UI, exports, and CLI rendering derive from `DomainReport`.

`LookupSnapshot` remains an internal collection and persistence shape. `DomainReport` is the stable presentation and export contract.

## Canonical Report Lifecycle

- `LookupRuntime` coordinates section services.
- `DomainInspectionService` normalizes failures, provenance, cache state, and section metadata.
- `DomainReportBuilder` adds summaries, insights, risk scoring, change analysis, workflow context, and report metadata.
- `DomainReportExporter` renders TXT, CSV, and JSON from the same report payload.
- `DomainDigCLI` prints exporter output directly so CLI output matches the app.

## Feature Tiers

The app now uses `FeatureAccessService` as the single feature gating surface.

- `Free`: single lookup, basic history, limited tracking
- `Pro`: workflows, batch operations, advanced exports
- `Data+`: future historical datasets and extended enrichment

Current release behavior is static scaffolding only. There are no purchases, backend checks, or remote entitlements.

## Data Boundaries

- Inspection services: network collection only
- `DomainReportBuilder`: canonical model assembly
- `FeatureAccessService`: tier and capability checks
- `DomainViewModel`: UI orchestration, persistence, batch coordination
- Views: rendering and interaction only

## Adding a New Data Source

1. Add the raw collection call to `LookupRuntime`.
2. Integrate it in `DomainInspectionService` with provenance, cache source, and normalized failures.
3. Extend `LookupSnapshot` only if the raw result must persist.
4. Add the summarized representation to `DomainReportBuilder`.
5. Expose it through `DomainReportExporter` if it should appear in TXT, CSV, JSON, or CLI.
6. Render the new summary in SwiftUI using `DomainReport` fields.
