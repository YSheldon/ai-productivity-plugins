from email import policy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path


root = Path(__file__).resolve().parent.parent
subject = "【猎鹰安全】每日漏洞播报｜2099-01-01"
html = """<!doctype html><html><body><table role="presentation" width="100%" style="width:100%;"><tr><td align="center"><table role="presentation" width="720" style="width:720px;max-width:96%;"><tr><td>【各源命中概览】可见 HTML 正文验证内容</td></tr></table></td></tr></table></body></html>"""

valid = MIMEMultipart("alternative")
valid["Subject"] = subject
valid.attach(MIMEText("【各源命中概览】可见纯文本正文验证内容" * 8, "plain", "utf-8"))
valid.attach(MIMEText(html * 4, "html", "utf-8"))
(root / "valid.eml").write_bytes(valid.as_bytes(policy=policy.SMTP))

invalid = MIMEMultipart("alternative")
invalid.attach(MIMEText("【各源命中概览】可见纯文本正文验证内容" * 8, "plain", "utf-8"))
invalid.attach(MIMEText(html * 4, "html", "utf-8"))
(root / "missing-subject.eml").write_bytes(invalid.as_bytes(policy=policy.SMTP))
