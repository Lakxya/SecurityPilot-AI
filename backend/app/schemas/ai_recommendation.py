from pydantic import BaseModel, Field

class ModelRecommendationRequest(BaseModel):
    doc_type: str = Field(default="README")
    cost_sensitivity: str | None = Field(default="NORMAL")  # LOW, NORMAL, HIGH
    speed_preference: str | None = Field(default="BALANCED")  # FAST, BALANCED, HIGH_REASONING

class ModelRecommendationResponse(BaseModel):
    recommended_provider: str
    recommended_model: str
    confidence_score: float  # 0.0 to 1.0
    rating_stars: int
    reason: str
    estimated_latency: str
    estimated_cost: str
    context_window: str
    security_suitability_score: int
    strengths: list[str]
    weaknesses: list[str]
    best_for_artifacts: list[str]
