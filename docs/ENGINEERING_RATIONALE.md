# TigerFetch engineering rationale

## Why Go

TigerFetch began as a Rust application and was ported to Go. Its main workload is operational ingestion: coordinating network requests, parsing heterogeneous data, managing rate limits and retries, writing to PostgreSQL and keeping a long-running service observable.

Go fits that workload through goroutines, context cancellation, standard HTTP support and a single-binary deployment model. The implementation keeps ingestion, configuration, storage and metrics in separate packages so that each pipeline can be understood and changed independently.

The migration preserved the original system's explicit data flow: collection, normalisation, storage and downstream analysis. Reliability still depends on bounded concurrency, input sanitisation, resumable ingestion, database consistency and visibility into failure modes. Language choice alone does not provide those properties.

## Platform boundaries

TigerFetch owns collection and storage. TigerEye handles enrichment and retrieval, while TigerWatch connects intelligence to products, versions and software bills of materials. These responsibilities guide the service boundaries and technology choices across TigerBlue.

## Product name and compatibility

TigerFetch is the public product name and the existing executable name. The `tiger2go` repository and Go module names record the migration's history and remain in place for compatibility with imports, documentation links and deployment tooling.

Database names, container identifiers, network names and volume names retain their configured values. This documentation change does not require a data migration or deployment configuration change.

See [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) for implementation details and [PROJECT_PLAN.md](../PROJECT_PLAN.md) for the migration plan and recorded progress.
