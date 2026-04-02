"""Dataset handling for EvoPrompt."""

import json
import os
from typing import List, Dict, Any, Optional, Tuple
from abc import ABC, abstractmethod
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class Sample:
    """Represents a single data sample."""

    def __init__(self, input_text: str, target: str, metadata: Optional[Dict] = None):
        self.input_text = input_text
        self.target = target
        self.metadata = metadata or {}

    def __repr__(self):
        return f"Sample(input='{self.input_text[:50]}...', target='{self.target}')"


class Dataset(ABC):
    """Abstract base class for datasets."""

    def __init__(self, name: str):
        self.name = name
        self._samples = []

    @abstractmethod
    def load_data(self, data_path: str) -> List[Sample]:
        """Load data from file."""
        pass

    def get_samples(self, n: Optional[int] = None) -> List[Sample]:
        """Get n samples (or all if n is None)."""
        if n is None:
            return self._samples
        return self._samples[:n]

    def __len__(self):
        return len(self._samples)


class PrimevulDataset(Dataset):
    """Dataset class for Primevul vulnerability detection data."""

    def __init__(self, data_path: str, split: str = "dev"):
        super().__init__(f"primevul_{split}")
        self.data_path = self._auto_fixed_path(data_path)
        self.split = split
        self._samples = self.load_data(self.data_path)

    @staticmethod
    def _detect_language_from_filename(file_name: Optional[str]) -> Optional[str]:
        """从文件名提取语言信息"""
        if not file_name or file_name == "None":
            return None

        # 扩展名到语言的映射
        ext_map = {
            'c': 'c',
            'h': 'c',  # C头文件
            'cpp': 'cpp',
            'cc': 'cpp',
            'cxx': 'cpp',
            'hpp': 'cpp',
            'hxx': 'cpp',
            'java': 'java',
            'py': 'python',
            'js': 'javascript',
            'ts': 'typescript',
            'go': 'go',
            'rs': 'rust',
        }

        # 提取扩展名
        if '.' in file_name:
            ext = file_name.rsplit('.', 1)[-1].lower()
            return ext_map.get(ext)

        return None

    @staticmethod
    def _detect_language_from_code(code: str) -> str:
        """基于代码特征的语言检测（备用方案）"""
        code_sample = code[:1000]  # 检查前1000字符以提高准确率

        # C/C++ 特征（增强版）
        c_cpp_indicators = [
            '#include', 'void ', 'int main', 'malloc', 'free', 'printf',
            'static ', 'uint32', 'int32', 'uint16', 'uint8',  # 常见C类型
            'typedef ', 'struct ', 'enum ', 'sizeof(',  # C结构
        ]
        cpp_indicators = ['::', 'std::', 'class ', 'namespace ', 'template<']

        # 先检查C++特征
        if any(ind in code_sample for ind in cpp_indicators):
            return 'cpp'

        # 检查C特征（更宽松的匹配）
        if any(ind in code_sample for ind in c_cpp_indicators):
            return 'c'

        # Java 特征
        java_indicators = ['public class', 'import java', 'System.out', 'package ', 'extends ', 'implements ']
        if any(ind in code_sample for ind in java_indicators):
            return 'java'

        # Python 特征
        python_indicators = ['def ', 'import ', 'from ', 'if __name__', 'print(']
        if any(ind in code_sample for ind in python_indicators):
            return 'python'

        # JavaScript 特征
        js_indicators = ['function ', 'const ', 'let ', '=>', 'require(', 'module.exports']
        if any(ind in code_sample for ind in js_indicators):
            return 'javascript'

        # 最后的启发式判断：如果看起来像系统级代码，可能是C
        # 检查是否有典型的C风格函数声明
        if 'static' in code_sample and '(' in code_sample and ')' in code_sample:
            return 'c'

        return 'unknown'

    @staticmethod
    def _auto_fixed_path(data_path: str):
        """优先查找 _fixed 文件，若无则用原文件名."""
        path_obj = Path(data_path)
        # 支持 jsonl/txt两类
        fixed = None
        if path_obj.suffix in {'.jsonl', '.txt'}:
            fixed_path = path_obj.with_name(f"{path_obj.stem}_fixed{path_obj.suffix}")
            if fixed_path.exists():
                fixed = str(fixed_path)
        return fixed or data_path

    def load_data(self, data_path: str) -> List[Sample]:
        """Load Primevul data from JSONL or tab-separated format."""
        samples = []

        if not os.path.exists(data_path):
            logger.warning(f"Data file not found: {data_path}")
            return samples

        path_obj = Path(data_path)
        metadata_path: Optional[Path] = None

        if path_obj.suffix.lower() in {".txt", ".tsv"}:
            # Attempt to locate companion JSONL file with full metadata
            companion_candidates = [
                path_obj.with_name(f"{path_obj.stem}_sample.jsonl"),
                path_obj.with_suffix(".jsonl"),
            ]

            for candidate in companion_candidates:
                if candidate.exists():
                    metadata_path = candidate
                    break

        metadata_file = None
        metadata_iter = None

        if metadata_path:
            try:
                metadata_file = open(metadata_path, "r", encoding="utf-8")

                def _metadata_generator():
                    for raw_line in metadata_file:
                        line = raw_line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError as exc:
                            logger.warning(
                                "Failed to parse metadata line in %s: %s",
                                metadata_path,
                                exc,
                            )
                            continue

                metadata_iter = _metadata_generator()
            except Exception as e:
                logger.warning(f"Failed to open metadata file: {metadata_path}: {e}")

        try:
            with open(data_path, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
                f.seek(0)  # Reset file pointer

                # Detect format based on first line
                if first_line.startswith("{"):
                    # JSONL format
                    for line in f:
                        if line.strip():
                            item = json.loads(line.strip())

                            # Extract function code and vulnerability label
                            func_code = item.get("func", "")
                            target = str(
                                item.get("target", 0)
                            )  # 0=benign, 1=vulnerable

                            # 两级语言检测：优先file_name，备用代码特征
                            file_name = item.get("file_name")
                            lang = self._detect_language_from_filename(file_name)
                            if not lang:
                                lang = self._detect_language_from_code(func_code)

                            # Create metadata
                            metadata = {
                                "idx": item.get("idx"),
                                "project": item.get("project"),
                                "commit_id": item.get("commit_id"),
                                "cwe": item.get("cwe", []),
                                "cve": item.get("cve"),
                                "func_hash": item.get("func_hash"),
                                "file_name": file_name,  # 保留原始文件名
                                "lang": lang,  # 新增：语言标识
                                # NL AST fields (if available from comment4vul processing)
                                "nl_ast": item.get("natural_language_ast") or item.get("clean_code") or item.get("nl_ast"),
                                "choices": item.get("choices"),  # Original commented code
                            }

                            sample = Sample(
                                input_text=func_code.strip(),
                                target=target,
                                metadata=metadata,
                            )
                            samples.append(sample)
                else:
                    # Tab-separated format
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue

                        parts = line.split("\t")
                        if len(parts) != 2:
                            logger.warning(f"Invalid format at line {line_num}: {line}")
                            continue

                        func_code, target = parts
                        target = target.strip()

                        # 初始化metadata，稍后会补充更多信息
                        metadata = {"line_num": line_num}

                        meta_record = None
                        if metadata_iter is not None:
                            try:
                                meta_record = next(metadata_iter)
                            except StopIteration:
                                logger.warning(
                                    "Companion metadata file %s has fewer entries than %s (stopped at line %d)",
                                    metadata_path,
                                    data_path,
                                    line_num,
                                )
                                metadata_iter = None

                        if meta_record:
                            metadata.update(
                                {
                                    "idx": meta_record.get("idx"),
                                    "project": meta_record.get("project"),
                                    "commit_id": meta_record.get("commit_id"),
                                    "cwe": meta_record.get("cwe", []),
                                    "cve": meta_record.get("cve"),
                                    "func_hash": meta_record.get("func_hash"),
                                }
                            )

                            raw_target = meta_record.get("target")
                            if raw_target is not None:
                                try:
                                    target = str(int(raw_target))
                                except (TypeError, ValueError):
                                    target = str(raw_target)

                            raw_code = meta_record.get("func")
                            if isinstance(raw_code, str) and raw_code.strip():
                                func_code = raw_code.strip()

                        # 两级语言检测
                        file_name = metadata.get("file_name")
                        lang = self._detect_language_from_filename(file_name)
                        if not lang:
                            lang = self._detect_language_from_code(func_code)
                        metadata["lang"] = lang

                        sample = Sample(
                            input_text=func_code.strip(),
                            target=target,
                            metadata=metadata,
                        )
                        samples.append(sample)

        except Exception as e:
            logger.error(f"Error loading data from {data_path}: {e}")
        finally:
            if metadata_file:
                remaining = 0
                if metadata_iter is not None:
                    for _ in metadata_iter:
                        remaining += 1
                if remaining > 0:
                    logger.warning(
                        "Companion metadata file %s has %d extra entries beyond %s",
                        metadata_path,
                        remaining,
                        data_path,
                    )
                metadata_file.close()


        logger.info(f"Loaded {len(samples)} samples from {data_path}")
        return samples


class BenchmarkDataset(Dataset):
    """Dataset class for benchmark vulnerability annotations stored as JSON."""

    def __init__(self, data_path: str, split: str = "dev"):
        super().__init__(f"benchmark_{split}")
        self.data_path = data_path
        self.split = split
        self._samples = self.load_data(data_path)

    def _parse_ground_truth(
        self, issues: List[Dict[str, Any]]
    ) -> Tuple[List[str], List[str], List[Dict[str, Any]]]:
        """Extract category names, CWE codes, and normalized issue metadata."""
        categories: List[str] = []
        cwe_codes: List[str] = []
        normalized_issues: List[Dict[str, Any]] = []

        for issue in issues:
            if not isinstance(issue, dict):
                continue

            category = issue.get("category")
            if category:
                categories.append(str(category))

            cwe_id = issue.get("cwe_id")
            if cwe_id is not None:
                try:
                    cwe_int = int(cwe_id)
                    cwe_codes.append(f"CWE-{cwe_int}")
                except (ValueError, TypeError):
                    # Skip malformed entries without aborting load
                    pass

            normalized_issues.append(
                {
                    "category": category,
                    "cwe_id": cwe_id,
                    "line": issue.get("line"),
                    "lineno": issue.get("lineno"),
                }
            )

        return categories, cwe_codes, normalized_issues

    def load_data(self, data_path: str) -> List[Sample]:
        """Load benchmark data from a JSON array."""
        samples: List[Sample] = []

        if not os.path.exists(data_path):
            logger.warning(f"Data file not found: {data_path}")
            return samples

        try:
            with open(data_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict) and "data" in data:
                # Allow wrapper format {"data": [...]}
                data = data["data"]

            if not isinstance(data, list):
                logger.error(f"Benchmark data should be a list, got {type(data)}")
                return samples

            for idx, item in enumerate(data):
                if not isinstance(item, dict):
                    logger.debug(f"Skipping non-dict entry at index {idx}")
                    continue

                raw_code = item.get("code", "")
                if not isinstance(raw_code, str):
                    raw_code = str(raw_code)
                code = raw_code.replace("\r\n", "\n").strip()

                issues = item.get("gt", []) or []
                categories, cwe_codes, normalized_issues = self._parse_ground_truth(
                    issues
                )
                has_vulnerability = bool(normalized_issues)

                # 语言检测：优先使用数据中的lang字段，缺失时使用代码检测
                lang = item.get("lang")
                if not lang:
                    # 使用PrimevulDataset的语言检测方法
                    lang = PrimevulDataset._detect_language_from_code(code)

                metadata: Dict[str, Any] = {
                    "index": item.get("index", idx),
                    "lang": lang,  # 确保lang字段总是有值
                    "source": item.get("source"),
                    "categories": categories,
                    "cwe": cwe_codes,
                    "issues": normalized_issues,
                    "false_positives": item.get("fp", []),
                }

                sample = Sample(
                    input_text=code,
                    target="1" if has_vulnerability else "0",
                    metadata=metadata,
                )
                samples.append(sample)

        except json.JSONDecodeError as exc:
            logger.error(f"Failed to parse benchmark JSON: {exc}")
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(f"Error loading data from {data_path}: {exc}")

        logger.info(f"Loaded {len(samples)} samples from {data_path}")
        return samples


class SVENDataset(Dataset):
    """Dataset class for SVEN vulnerability detection data."""

    def __init__(self, data_path: str, split: str = "dev"):
        super().__init__(f"sven_{split}")
        self.data_path = data_path
        self.split = split
        self._samples = self.load_data(data_path)

    def load_data(self, data_path: str) -> List[Sample]:
        """Load SVEN data from tab-separated format."""
        samples = []

        if not os.path.exists(data_path):
            logger.warning(f"Data file not found: {data_path}")
            return samples

        try:
            with open(data_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split("\t")
                    if len(parts) != 2:
                        logger.warning(f"Invalid format at line {line_num}: {line}")
                        continue

                    func_code, target = parts

                    sample = Sample(
                        input_text=func_code.strip(),
                        target=target.strip(),
                        metadata={"line_num": line_num},
                    )
                    samples.append(sample)

        except Exception as e:
            logger.error(f"Error loading data from {data_path}: {e}")

        logger.info(f"Loaded {len(samples)} samples from {data_path}")
        return samples


class TextClassificationDataset(Dataset):
    """General text classification dataset."""

    def __init__(self, data_path: str, split: str = "dev"):
        super().__init__(f"text_cls_{split}")
        self.data_path = data_path
        self.split = split
        self._samples = self.load_data(data_path)

    def load_data(self, data_path: str) -> List[Sample]:
        """Load text classification data."""
        samples = []

        if not os.path.exists(data_path):
            logger.warning(f"Data file not found: {data_path}")
            return samples

        try:
            with open(data_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split("\t")
                    if len(parts) >= 2:
                        text = parts[0].strip()
                        label = parts[1].strip()

                        sample = Sample(
                            input_text=text,
                            target=label,
                            metadata={"line_num": line_num},
                        )
                        samples.append(sample)

        except Exception as e:
            logger.error(f"Error loading data from {data_path}: {e}")

        logger.info(f"Loaded {len(samples)} samples from {data_path}")
        return samples


def create_dataset(dataset_name: str, data_path: str, split: str = "dev") -> Dataset:
    """Factory function to create datasets."""
    dataset_name = dataset_name.lower()

    if dataset_name == "primevul":
        return PrimevulDataset(data_path, split)
    if dataset_name == "benchmark":
        return BenchmarkDataset(data_path, split)
    if dataset_name == "sven":
        return SVENDataset(data_path, split)
    return TextClassificationDataset(data_path, split)


def prepare_primevul_data(primevul_dir: str, output_dir: str) -> Tuple[str, str]:
    """Prepare Primevul data for EvoPrompt format."""
    primevul_dir = Path(primevul_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Convert JSONL to tab-separated format
    dev_file = primevul_dir / "dev.jsonl"
    test_file = primevul_dir / "primevul_test.jsonl"

    dev_output = output_dir / "dev.txt"
    test_output = output_dir / "test.txt"

    def convert_jsonl_to_txt(input_file: Path, output_file: Path):
        """Convert JSONL format to tab-separated format."""
        if not input_file.exists():
            logger.warning(f"Input file not found: {input_file}")
            return

        with open(input_file, "r", encoding="utf-8") as f_in, open(
            output_file, "w", encoding="utf-8"
        ) as f_out:
            for line in f_in:
                if line.strip():
                    item = json.loads(line.strip())
                    func_code = item.get("func", "").strip()
                    target = str(item.get("target", 0))

                    # Clean up function code for single line format
                    func_code = func_code.replace("\n", " ").replace("\t", " ")
                    while "  " in func_code:
                        func_code = func_code.replace("  ", " ")

                    f_out.write(f"{func_code}\t{target}\n")

    # Convert files
    if dev_file.exists():
        convert_jsonl_to_txt(dev_file, dev_output)
        logger.info(f"Converted dev data: {dev_output}")

    if test_file.exists():
        convert_jsonl_to_txt(test_file, test_output)
        logger.info(f"Converted test data: {test_output}")
    else:
        # Use dev as test if test doesn't exist
        if dev_output.exists():
            import shutil

            shutil.copy2(dev_output, test_output)
            logger.info(f"Copied dev data as test: {test_output}")

    return str(dev_output), str(test_output)
