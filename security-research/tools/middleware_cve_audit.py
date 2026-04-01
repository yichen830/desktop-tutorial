import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    cve: str
    product: str
    affected_versions: tuple[str, ...]
    risky_exposures: tuple[str, ...]
    summary: str
    remediation: str


RULES = (
    Rule(
        cve="CVE-2020-1938",
        product="tomcat",
        affected_versions=("6.", "7.", "8.5.0-8.5.50", "9.0.0-9.0.30"),
        risky_exposures=("8009", "ajp"),
        summary="Tomcat AJP 暴露可能带来高风险访问面，需优先确认 AJP 是否启用且是否对不可信网络开放。",
        remediation="关闭不必要的 AJP Connector，仅允许可信来源访问，并升级到已修复版本。",
    ),
    Rule(
        cve="CVE-2022-26134",
        product="confluence",
        affected_versions=("7.4.0-7.4.17", "7.13.0-7.13.7", "7.14.0-7.14.3", "7.15.0-7.15.2", "7.16.0-7.16.4", "7.17.0-7.17.4", "8.0.0-8.0.0"),
        risky_exposures=("internet", "443", "8443"),
        summary="Confluence 风险版本若直接暴露互联网，应优先做补丁、凭据轮换与入侵痕迹排查。",
        remediation="升级到官方修复版本，收紧公网访问，并审计管理员、插件和关联凭据。",
    ),
    Rule(
        cve="CVE-2023-50164",
        product="struts2",
        affected_versions=("2.0.0-2.3.37", "2.5.0-2.5.32", "6.0.0-6.3.0.1"),
        risky_exposures=("upload-enabled", "80", "443"),
        summary="Struts 2 上传链路若处于风险版本，需重点核查文件上传功能与落盘路径隔离情况。",
        remediation="升级框架版本，隔离上传目录，审计历史上传文件，并加强网关侧检测。",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="中间件 CVE 防御排查脚本：根据资产清单输出版本与暴露面风险提示。"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="JSON 资产清单路径，格式参考 security-research/examples/inventory.json",
    )
    return parser.parse_args()


def load_inventory(path: Path) -> list[dict]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        print(f"[错误] 找不到输入文件: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"[错误] JSON 解析失败: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, list):
        print("[错误] 输入文件必须是 JSON 数组。", file=sys.stderr)
        sys.exit(1)

    return data


def version_in_range(version: str, spec: str) -> bool:
    if "-" not in spec:
        return version.startswith(spec)

    start, end = spec.split("-", 1)
    return normalize_version(start) <= normalize_version(version) <= normalize_version(end)


def normalize_version(version: str) -> tuple[int, ...]:
    parts = []
    for item in version.split("."):
        digits = "".join(ch for ch in item if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def any_exposure_matches(exposure: Iterable[str], risky_keywords: Iterable[str]) -> bool:
    lowered = [item.lower() for item in exposure]
    return any(keyword.lower() in entry for keyword in risky_keywords for entry in lowered)


def evaluate_asset(asset: dict) -> list[str]:
    name = str(asset.get("name", "unknown"))
    product = str(asset.get("product", "")).lower()
    version = str(asset.get("version", ""))
    exposure = [str(item) for item in asset.get("exposure", [])]

    findings: list[str] = []
    for rule in RULES:
        if product != rule.product:
            continue

        version_hit = any(version_in_range(version, spec) for spec in rule.affected_versions)
        exposure_hit = any_exposure_matches(exposure, rule.risky_exposures)

        if version_hit:
            findings.append(
                "\n".join(
                    (
                        f"- 资产: {name}",
                        f"- 产品: {product}",
                        f"- 版本: {version}",
                        f"- 关联 CVE: {rule.cve}",
                        f"- 版本判断: 命中风险区间",
                        f"- 暴露面判断: {'存在高风险暴露面' if exposure_hit else '未发现明显高风险暴露面，但仍需人工复核'}",
                        f"- 风险说明: {rule.summary}",
                        f"- 建议动作: {rule.remediation}",
                    )
                )
            )
        elif exposure_hit:
            findings.append(
                "\n".join(
                    (
                        f"- 资产: {name}",
                        f"- 产品: {product}",
                        f"- 版本: {version or '未知'}",
                        f"- 关联 CVE: {rule.cve}",
                        f"- 版本判断: 未命中内置风险区间或版本信息不足",
                        f"- 暴露面判断: 存在需要关注的暴露面",
                        f"- 风险说明: 暴露面与该类漏洞的常见高风险入口重合，建议尽快核对精确补丁状态。",
                        f"- 建议动作: {rule.remediation}",
                    )
                )
            )

    if not findings:
        findings.append(
            "\n".join(
                (
                    f"- 资产: {name}",
                    f"- 产品: {product or '未知'}",
                    f"- 版本: {version or '未知'}",
                    "- 结果: 未命中当前脚本内置规则",
                    "- 提醒: 这不代表没有风险，只表示未命中当前内置的三类中间件漏洞规则。",
                )
            )
        )

    return findings


def main() -> None:
    args = parse_args()
    inventory = load_inventory(Path(args.input))

    print("# 中间件 CVE 防御排查报告")
    print()
    print(f"- 资产数量: {len(inventory)}")
    print(f"- 内置规则数: {len(RULES)}")
    print("- 说明: 结果用于防御排查与版本核验，不代表完整漏洞结论。")
    print()

    for index, asset in enumerate(inventory, start=1):
        print(f"## 资产 {index}")
        print()
        for finding in evaluate_asset(asset):
            print(finding)
            print()


if __name__ == "__main__":
    main()
