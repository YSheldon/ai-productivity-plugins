# GitLab CI Optimization Analysis

The plugin separates configuration structure from observed runtime behavior:

- `gitlab_analyze_ci_config` calls the project CI Lint API with
  `include_jobs=true`. It returns job names, stages, tags, `needs`, `when`, and
  `allow_failure` only. It never returns scripts, variables, include content,
  or merged YAML.
- `gitlab_analyze_pipeline_efficiency` reads one pipeline's job timing data and
  reports total execution time, queue time, wall-clock duration, approximate
  concurrency, per-stage metrics, and the largest queue waits. It never returns
  traces, Runner objects, users, or raw job responses.

Use both before proposing changes. CI Lint cannot prove queue capacity, cache
hit rate, or the critical path. One pipeline is an observation, not a trend;
compare representative pipelines before and after a change.

## Matrix Builds

Use `parallel:matrix` when the same job must run across independent, bounded
dimensions such as operating system, runtime version, architecture, or feature
mode. Keep the matrix small enough for available Runner capacity. A larger
matrix can increase queue time and total compute even when the YAML is shorter.

Use ordinary `needs` entries when compatibility matters across GitLab versions.
Matrix expressions provide one-to-one dependencies but require a GitLab version
that supports them; verify the instance version before proposing that syntax.

## Cache Strategy

Treat caches as an optimization, never as required evidence. Prefer
content-derived keys such as `cache:key:files` on lock files. A branch name by
itself often creates stale or low-reuse caches. Separate dependency caches from
build outputs, use `policy: pull` for consumers when a controlled producer owns
updates, and keep a fallback path that works on a cold or missing cache.

Never cache approval results, security findings, signatures, provenance, or
release-gate decisions.

## DAG Scheduling

Stages are useful for broad ordering, but stage-only scheduling makes every job
wait for the slowest job in the previous stage. Add `needs` only where the
dependency is real so independent work can start earlier. Measure the resulting
wall-clock and queue time; insufficient Runner capacity can turn intended
parallelism into additional waiting.

## Rules and Change Detection

Use `rules:changes` for expensive jobs whose inputs are well understood. Include
shared configuration, lock files, build scripts, and generated-code inputs in
the change set. Define behavior for schedules, tags, manually started pipelines,
and new branches instead of assuming merge request semantics everywhere.

Do not apply `rules:changes` to approval, security, signing, provenance,
compliance, or release gates. Those jobs must run for every relevant candidate.

## References

- GitLab CI Lint API: https://docs.gitlab.com/api/lint/
- GitLab CI/CD YAML syntax: https://docs.gitlab.com/ci/yaml/
- YAML optimization: https://docs.gitlab.com/ci/yaml/yaml_optimization/
- Job dependencies: https://docs.gitlab.com/ci/yaml/needs/
- Caching: https://docs.gitlab.com/ci/caching/
- Matrix expressions: https://docs.gitlab.com/ci/yaml/matrix_expressions/
- Job rules: https://docs.gitlab.com/ci/jobs/job_rules/
