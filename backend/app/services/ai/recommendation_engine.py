from app.models.project import Project
from app.schemas.ai_recommendation import ModelRecommendationResponse

class ProviderRecommendationService:
    @staticmethod
    def recommend_for_project(
        project: Project,
        doc_type: str = "README",
        cost_sensitivity: str = "NORMAL",
        speed_preference: str = "BALANCED",
    ) -> ModelRecommendationResponse:
        doc_type_upper = doc_type.upper()

        # Heuristic Smart Rules Matrix
        if doc_type_upper in ["THREAT_MODEL", "STRIDE_REVIEW", "OWASP_REVIEW", "ARCHITECTURE_SPEC", "COMPLIANCE_MATRIX"]:
            return ModelRecommendationResponse(
                recommended_provider="ANTHROPIC",
                recommended_model="Claude 3.5 Sonnet",
                confidence_score=0.98,
                rating_stars=5,
                reason=(
                    f"Claude 3.5 Sonnet excels at high-reasoning cybersecurity architecture analysis, "
                    f"threat vector modeling, and {', '.join(project.compliance_frameworks or ['NIST'])} compliance validation."
                ),
                estimated_latency="Fast (1.1s)",
                estimated_cost="Low ($0.003 / 1k tokens)",
                context_window="200k tokens",
                security_suitability_score=98,
                strengths=[
                    "Industry leader in threat vector analysis",
                    "Superior long-context reasoning for multi-tier architectures",
                    "Zero data retention guarantees for Enterprise tier",
                ],
                weaknesses=["Slightly higher latency on massive multi-file outputs"],
                best_for_artifacts=["STRIDE Threat Model", "OWASP Review", "System Security Plan", "Compliance Audit Matrix"],
            )
        elif doc_type_upper in ["DOCKERFILE", "DOCKER_COMPOSE", "GITHUB_ACTIONS"]:
            return ModelRecommendationResponse(
                recommended_provider="OPENAI",
                recommended_model="GPT-4o",
                confidence_score=0.95,
                rating_stars=5,
                reason=(
                    "GPT-4o provides industry-leading zero-shot precision for Docker containerization, "
                    "multi-stage build optimizations, and GitHub Actions CI/CD pipeline automation."
                ),
                estimated_latency="Ultra Fast (0.8s)",
                estimated_cost="Low ($0.0025 / 1k tokens)",
                context_window="128k tokens",
                security_suitability_score=96,
                strengths=[
                    "Highest accuracy for multi-stage Docker builds",
                    "Native support for shell script hardening and pin-digest tags",
                    "Fastest token generation rate",
                ],
                weaknesses=["Smaller context window than Claude Opus"],
                best_for_artifacts=["Dockerfile", "docker-compose.yml", "ci.yml", "Bash Scripts"],
            )
        elif doc_type_upper in ["TERRAFORM", "KUBERNETES"]:
            return ModelRecommendationResponse(
                recommended_provider="ANTHROPIC",
                recommended_model="Claude 3.5 Sonnet",
                confidence_score=0.96,
                rating_stars=5,
                reason=(
                    "Claude 3.5 Sonnet provides flawless HCL Terraform syntax validation, "
                    "Kubernetes RBAC least-privilege policies, and CloudTrail audit integration."
                ),
                estimated_latency="Fast (1.2s)",
                estimated_cost="Low ($0.003 / 1k tokens)",
                context_window="200k tokens",
                security_suitability_score=97,
                strengths=[
                    "Flawless HCL / Terraform HCL syntax validation",
                    "Enforces CIS Kubernetes Hardening Benchmark rules",
                    "Generates compliant NetworkPolicy manifests",
                ],
                weaknesses=["Higher cost for continuous dev testing"],
                best_for_artifacts=["main.tf", "deployment.yaml", "K8s NetworkPolicies", "IAM Roles"],
            )
        elif cost_sensitivity.upper() == "HIGH":
            return ModelRecommendationResponse(
                recommended_provider="OPENAI",
                recommended_model="GPT-4o Mini",
                confidence_score=0.91,
                rating_stars=4,
                reason="GPT-4o Mini delivers fast, cost-optimized generation for lightweight documentation and draft reviews.",
                estimated_latency="Instant (0.4s)",
                estimated_cost="Ultra Low ($0.00015 / 1k tokens)",
                context_window="128k tokens",
                security_suitability_score=91,
                strengths=["Minimal token cost", "Instant response latency", "Great for rapid iterative edits"],
                weaknesses=["Slightly lower reasoning depth on complex multi-cloud IaC"],
                best_for_artifacts=["README", "Glossary", "Quick Summaries"],
            )
        else:
            return ModelRecommendationResponse(
                recommended_provider="OPENAI",
                recommended_model="GPT-4.1",
                confidence_score=0.94,
                rating_stars=5,
                reason=(
                    f"GPT-4.1 is balanced for multi-file project documentation, "
                    f"stack specs ({project.tech_stack}), and developer setup guides."
                ),
                estimated_latency="Fast (0.9s)",
                estimated_cost="Moderate ($0.005 / 1k tokens)",
                context_window="1M tokens",
                security_suitability_score=95,
                strengths=["Massive 1M token context capacity", "Strong markdown and mermaid diagram rendering"],
                weaknesses=["Higher cost for small single-file prompts"],
                best_for_artifacts=["README", "Data Flow Diagram", "System Architecture Spec"],
            )
