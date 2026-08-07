from pydantic import BaseModel, Field

class CompareRequest(BaseModel):
    artifact: str = Field(default="THREAT_MODEL")
    providers: list[str] = Field(default_factory=lambda: ["openai", "anthropic"])
    custom_instructions: str | None = None

class ProviderQualityScore(BaseModel):
    provider: str
    model: str
    overall_quality_score: int  # 0 to 100
    reasoning_score: int
    security_score: int
    completeness_score: int
    compliance_coverage: int
    word_count: int
    generation_time_sec: float
    estimated_cost: str

class CompareResultSummary(BaseModel):
    artifact: str
    winner_provider: str
    winner_reason: str
    scores: list[ProviderQualityScore]
