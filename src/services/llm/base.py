from abc import ABC, abstractmethod

class LLMProvider(ABC):
    @abstractmethod
    async def complete(self, prompt: str) -> str:
        """
        Complete the prompt and return the full text response.
        """
        pass
    
    # Streaming support deferred to next iteration
    # @abstractmethod
    # async def stream(self, prompt: str):
    #     pass
