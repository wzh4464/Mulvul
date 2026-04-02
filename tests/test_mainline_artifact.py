from evoprompt.mainline.artifacts import PromptArtifact


def test_prompt_artifact_splits_levels():
    artifact = PromptArtifact.from_mapping(
        {
            "prompts": {
                "major_Memory": "major-memory",
                "major_Injection": "major-injection",
                "middle_Buffer Errors": "middle-buffer",
                "cwe_CWE-120": "cwe-120",
            },
            "scores": {
                "major_Memory": 0.8,
            },
        }
    )

    assert artifact.router_prompts == {
        "Memory": "major-memory",
        "Injection": "major-injection",
    }
    assert artifact.middle_prompts == {"Buffer Errors": "middle-buffer"}
    assert artifact.cwe_prompts == {"CWE-120": "cwe-120"}
    assert artifact.scores["major_Memory"] == 0.8
