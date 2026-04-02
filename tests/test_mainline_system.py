from evoprompt.mainline.artifacts import PromptArtifact
from evoprompt.mainline.system import MainlineDetectorSystem


class StubLLMClient:
    def generate(self, prompt: str, **kwargs) -> str:
        if "specializing in Memory vulnerabilities" in prompt:
            return '{"predictions":[{"category":"Memory","confidence":0.91}]}'
        if "specializing in Injection vulnerabilities" in prompt:
            return '{"predictions":[{"category":"Benign","confidence":0.80}]}'
        if "Buffer Errors vulnerability expert" in prompt:
            return '{"predictions":[{"category":"Buffer Errors","confidence":0.84}]}'
        if "Possible CWEs: CWE-119, CWE-120, CWE-125, CWE-787, CWE-805, Benign" in prompt:
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
