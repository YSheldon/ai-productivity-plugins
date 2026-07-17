from __future__ import annotations

from typing import Any


def parse_fallback_mail(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("事件："):
            event_text = line.split("：", 1)[1].strip()
            if "#" in event_text:
                event_id, round_id = event_text.split("#", 1)
                result["event_id"] = event_id.strip()
                if round_id.strip().isdigit():
                    result["round_id"] = int(round_id.strip())
        elif line.startswith("任务："):
            result["task"] = line.split("：", 1)[1].strip()
        elif line.startswith("模块："):
            result["module"] = line.split("：", 1)[1].strip()
        elif line.startswith("状态："):
            result["status"] = line.split("：", 1)[1].strip()
        elif line.startswith("测试结论："):
            result["test_result"] = line.split("：", 1)[1].strip()
        elif line.startswith("发起标识："):
            result["origin_badge"] = line.split("：", 1)[1].strip()
        elif line.startswith("提测人邮箱："):
            result["submitter_email"] = line.split("：", 1)[1].strip()
        elif line.startswith("Manifest-S："):
            result["manifest_s_digest"] = line.split("：", 1)[1].strip()
        elif line.startswith("Manifest-R："):
            result["manifest_r_digest"] = line.split("：", 1)[1].strip()
        elif line.startswith("- 提测门禁策略摘要："):
            result["submission_policy_digest"] = line.split("：", 1)[1].strip()
        elif line.startswith("- 预发布策略摘要："):
            result["pre_release_policy_digest"] = line.split("：", 1)[1].strip()
        elif line.startswith("- 发布门禁策略摘要："):
            result["gate_policy_digest"] = line.split("：", 1)[1].strip()
        elif line.startswith("- GitLab："):
            result["gitlab_evidence_ref"] = line.split("：", 1)[1].strip()
            result.setdefault("retrieval_method", "build")
        elif line.startswith("- SVN："):
            svn_value = line.split("：", 1)[1].strip()
            result["retrieval_method"] = "svn"
            if "@" in svn_value:
                repository_path, revision = svn_value.rsplit("@", 1)
                result["retrieval_provenance"] = {
                    "repository_path": repository_path.strip(),
                    "revision": revision.strip(),
                }
        elif line.startswith("- 飞书："):
            result["lark_evidence_ref"] = line.split("：", 1)[1].strip()
    return result
