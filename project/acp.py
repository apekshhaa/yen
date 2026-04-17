"""ACP server configuration for the Major-Project AI Pentester Agent."""
import os

from temporalio.contrib.openai_agents import OpenAIAgentsPlugin

from agentex.lib.sdk.fastacp.fastacp import FastACP
from agentex.lib.types.fastacp import TemporalACPConfig
from agentex.lib.core.temporal.plugins.openai_agents.models.temporal_streaming_model import (
    TemporalStreamingModelProvider,
)
from agentex.lib.core.temporal.plugins.openai_agents.interceptors.context_interceptor import (
    ContextInterceptor,
)

# Initialize OpenAI Agents SDK integration components
# ContextInterceptor: Threads task_id through activity headers for streaming context
# TemporalStreamingModelProvider: Returns models that stream tokens to Redis in real-time
context_interceptor = ContextInterceptor()
temporal_streaming_model_provider = TemporalStreamingModelProvider()

# Create the ACP server with OpenAI Agents SDK plugin
acp = FastACP.create(
    acp_type="async",
    config=TemporalACPConfig(
        type="temporal",
        temporal_address=os.getenv("TEMPORAL_ADDRESS", "localhost:7233"),
        plugins=[OpenAIAgentsPlugin(model_provider=temporal_streaming_model_provider)],
        interceptors=[context_interceptor],
    ),
)
