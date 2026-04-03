from mulvul.mainline.artifacts import PromptArtifact
from mulvul.mainline.bundle import PromptBundleAdapter
from mulvul.mainline.system import MainlineDetectorSystem


class StubLLMClient:
    def generate(self, prompt: str, **kwargs) -> str:
        if "specializing in Memory vulnerabilities" in prompt:
            return '{"predictions":[{"category":"Memory","confidence":0.91}]}'
        if "specializing in Injection vulnerabilities" in prompt:
            return '{"predictions":[{"category":"Benign","confidence":0.80}]}'
        if "Buffer Errors vulnerability expert" in prompt:
            return '{"predictions":[{"category":"Buffer Errors","confidence":0.84}]}'
        if "Possible CWEs:" in prompt and "CWE-120" in prompt:
            return '{"predictions":[{"cwe":"CWE-120","confidence":0.88}]}'
        return '{"predictions":[{"category":"Benign","confidence":0.70}]}'

    def batch_generate(self, prompts, **kwargs):
        return [self.generate(prompt, **kwargs) for prompt in prompts]


def test_mainline_detector_returns_best_router_detector_path():
    artifact = PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": "You are a security expert specializing in Memory vulnerabilities.\n{evidence}\n{code}\n{candidates}",
                "major_Injection": "You are a security expert specializing in Injection vulnerabilities.\n{evidence}\n{code}\n{candidates}",
                "middle_Buffer Errors": "You are a Buffer Errors vulnerability expert.\n{evidence}\n{code}\n{candidates}",
                "cwe_CWE-120": "You are a vulnerability expert. Identify if this code has CWE-120.\n## Possible CWEs: {candidates}\n{evidence}\n{code}",
            }
        }
    )
    system = MainlineDetectorSystem(StubLLMClient(), artifact)

    result = system.detect("strcpy(buf, input);")

    assert result.major == "Memory"
    assert result.middle == "Buffer Errors"
    assert result.cwe == "CWE-120"
    assert result.prediction == "CWE-120"


def test_mainline_detector_uses_null_descendants_for_benign():
    class BenignOnlyClient:
        def generate(self, prompt: str, **kwargs) -> str:
            return '{"predictions":[{"category":"Benign","confidence":0.95}]}'

    artifact = PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": "You are a security expert specializing in Memory vulnerabilities.\n{evidence}\n{code}\n{candidates}",
                "major_Injection": "You are a security expert specializing in Injection vulnerabilities.\n{evidence}\n{code}\n{candidates}",
            }
        }
    )
    system = MainlineDetectorSystem(BenignOnlyClient(), artifact)

    result = system.detect("int x = 0;")

    assert result.prediction == "Benign"
    assert result.major == "Benign"
    assert result.middle is None
    assert result.cwe is None
    assert result.to_dict()["middle"] is None
    assert result.to_dict()["cwe"] is None


def test_mainline_detector_matches_between_v1_artifact_and_v2_bundle():
    artifact = PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": "You are a security expert specializing in Memory vulnerabilities.\n{evidence}\n{code}\n{candidates}",
                "major_Injection": "You are a security expert specializing in Injection vulnerabilities.\n{evidence}\n{code}\n{candidates}",
                "middle_Buffer Errors": "You are a Buffer Errors vulnerability expert.\n{evidence}\n{code}\n{candidates}",
                "cwe_CWE-120": "You are a vulnerability expert. Identify if this code has CWE-120.\n## Possible CWEs: {candidates}\n{evidence}\n{code}",
            }
        }
    )
    bundle = PromptBundleAdapter.from_artifact(artifact, allow_partial=True)

    artifact_result = MainlineDetectorSystem(StubLLMClient(), artifact).detect(
        "strcpy(buf, input);"
    )
    bundle_result = MainlineDetectorSystem(
        StubLLMClient(),
        bundle,
    ).detect("strcpy(buf, input);")

    assert artifact_result.to_dict() == bundle_result.to_dict()
