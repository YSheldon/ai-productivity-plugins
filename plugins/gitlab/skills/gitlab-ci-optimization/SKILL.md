---
name: gitlab-ci-optimization
description: Analyze and optimize GitLab CI pipelines using sanitized CI Lint structure and observed job timings, with careful use of matrices, content-derived caches, needs DAGs, and rules:changes that never bypass security or release gates.
---

# GitLab CI Optimization

Use this workflow when asked to reduce GitLab pipeline latency, queueing,
duplication, or compute cost.

## Evidence First

1. Call `gitlab_test_connection` and record the GitLab version.
2. Call `gitlab_analyze_ci_config` for the candidate ref.
3. Call `gitlab_analyze_pipeline_efficiency` for representative successful and
   slow pipelines.
4. Read `.gitlab-ci.yml` and relevant included YAML only when needed to inspect
   cache keys, rules, or matrix definitions. Do not quote secrets.
5. State separately what CI Lint proves, what observed timings show, and what
   remains unmeasured.

## Change Selection

- Use `parallel:matrix` for bounded, independent variants with available Runner
  capacity. More jobs do not guarantee a faster pipeline.
- Prefer `cache:key:files` based on lock files or other dependency inputs. Keep
  cold-cache behavior correct and never treat cache content as evidence.
- Use `needs` for real dependencies so independent jobs can start without a
  stage-wide barrier.
- Use `rules:changes` only for jobs with complete, reviewed input paths and
  explicit non-MR behavior.
- Verify instance support before using matrix expressions or other
  version-dependent syntax.

Never skip or cache approval, security, signing, provenance, compliance, or
release gates. The MR approval/scope job must run once for every relevant
candidate and must query GitLab live with `CI_JOB_TOKEN`.

Validate proposed YAML through GitLab CI Lint and compare queue, wall-clock,
execution, failure, and retry observations after rollout. Read
`../../docs/ci-optimization-analysis.md` for detailed tradeoffs and official
references.
