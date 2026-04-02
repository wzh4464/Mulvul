"""Async LLM client for high-performance concurrent requests"""

import asyncio
import aiohttp
import time
import logging
import os
from typing import Dict, Any, Optional, List, Union
from pathlib import Path

logger = logging.getLogger(__name__)


def load_env_vars():
    """Load environment variables from .env file"""
    # Try multiple possible locations for .env file
    possible_paths = [
        Path(__file__).parent.parent.parent / '.env',  # From package structure
        Path.cwd() / '.env',  # From current working directory
        Path(__file__).parent.parent.parent.parent / '.env'  # One level up from src
    ]
    
    for env_path in possible_paths:
        if env_path.exists():
            logger.debug(f"Loading .env from: {env_path}")
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
            return
    
    logger.warning("No .env file found in any expected location")


# Load environment variables at module level
load_env_vars()


class AsyncLLMClient:
    """High-performance async LLM client with concurrency control"""
    
    def __init__(
        self,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        max_concurrency: int = 16,  # Based on test results
        max_retries: int = 3,
        retry_delay: float = 1.0,
        timeout: float = 30.0
    ):
        # Get configuration from environment or parameters
        self.api_base = api_base or os.getenv("API_BASE_URL", "https://api.chatanywhere.tech/v1")
        self.api_key = api_key or os.getenv("API_KEY", "")
        self.model_name = model_name or os.getenv("MODEL_NAME", "gpt-3.5-turbo")
        self.backup_api_base = os.getenv("BACKUP_API_BASE_URL", "https://newapi.aicohere.org/v1")
        
        self.max_concurrency = max_concurrency
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        
        if not self.api_key:
            raise ValueError("API_KEY not found. Please set it in .env file or environment variable.")
        
        # Session will be created when needed
        self._session = None
        self._semaphore = None
        
        logger.info(f"Initialized Async LLM Client with model: {self.model_name}")
        logger.info(f"Max concurrency: {self.max_concurrency}")
        logger.info(f"Primary API: {self.api_base}")
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=100,
                limit_per_host=self.max_concurrency + 10,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=headers
            )
            
            # Create semaphore for concurrency control
            self._semaphore = asyncio.Semaphore(self.max_concurrency)
        
        return self._session
    
    async def _make_request(self, messages: List[Dict], temperature: float = 0.1, max_tokens: int = None) -> str:
        """Make async API request with fallback support."""
        session = await self._get_session()
        
        data = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature
        }
        if max_tokens is not None:
            data["max_tokens"] = max_tokens
        
        # Try primary API first, then backup API
        apis_to_try = [self.api_base, self.backup_api_base]
        
        for attempt in range(self.max_retries):
            for api_base in apis_to_try:
                try:
                    async with session.post(
                        f"{api_base}/chat/completions",
                        json=data
                    ) as response:
                        
                        if response.status == 200:
                            result = await response.json()
                            content = result['choices'][0]['message']['content'].strip()
                            logger.debug(f"Successful API call to {api_base}")
                            return content
                        else:
                            error_text = await response.text()
                            logger.warning(f"API call failed for {api_base} (attempt {attempt + 1}): HTTP {response.status} - {error_text[:100]}")
                            
                except Exception as e:
                    logger.warning(f"API call failed for {api_base} (attempt {attempt + 1}): {e}")
                    if api_base == apis_to_try[-1] and attempt == self.max_retries - 1:
                        raise Exception(f"All API endpoints failed after {self.max_retries} attempts. Last error: {e}")
                    continue
            
            # Wait before next retry with exponential backoff
            if attempt < self.max_retries - 1:
                await asyncio.sleep(self.retry_delay * (2 ** attempt))
        
        raise Exception("All API endpoints and retries exhausted")
    
    async def generate_async(self, prompt: str, **kwargs) -> str:
        """Generate text from a single prompt asynchronously."""
        # Ensure session is initialized
        await self._get_session()
        
        messages = [{"role": "user", "content": prompt}]
        
        # Extract parameters
        temperature = kwargs.get("temperature", 0.1)
        max_tokens = kwargs.get("max_tokens", None)
        task = kwargs.get("task", False)
        
        # Use semaphore to control concurrency
        async with self._semaphore:
            result = await self._make_request(messages, temperature, max_tokens)
        
        # Task-oriented truncation (like SVEN)
        if task:
            result = result.split("\n\n")[0]
        
        return result
    
    async def batch_generate_async(
        self, 
        prompts: List[str], 
        show_progress: bool = True,
        **kwargs
    ) -> List[str]:
        """Generate text for multiple prompts concurrently."""
        
        async def generate_with_semaphore(prompt: str, index: int) -> str:
            try:
                result = await self.generate_async(prompt, **kwargs)
                if show_progress and (index + 1) % 10 == 0:
                    logger.info(f"Processed {index + 1}/{len(prompts)} queries")
                return result
            except Exception as e:
                logger.error(f"Query {index + 1} failed: {e}")
                return "error"
        
        # Create tasks for all prompts
        tasks = [
            generate_with_semaphore(prompt, i) 
            for i, prompt in enumerate(prompts)
        ]
        
        # Execute all tasks concurrently
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        # Convert exceptions to error strings
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Task failed: {result}")
                processed_results.append("error")
            else:
                processed_results.append(result)
        
        # Log performance stats
        duration = end_time - start_time
        successful_requests = sum(1 for r in processed_results if r != "error")
        requests_per_second = len(prompts) / duration if duration > 0 else 0
        
        logger.info(f"Batch completed: {successful_requests}/{len(prompts)} successful in {duration:.2f}s ({requests_per_second:.2f} req/s)")
        
        return processed_results
    
    async def paraphrase_async(self, sentence: Union[str, List[str]], temperature: float = 0.7) -> Union[str, List[str]]:
        """Paraphrase sentences while keeping semantic meaning."""
        if isinstance(sentence, list):
            prompts = [
                f"Generate a variation of the following instruction while keeping the semantic meaning.\nInput: {s}\nOutput:"
                for s in sentence
            ]
            return await self.batch_generate_async(prompts, temperature=temperature)
        else:
            prompt = f"Generate a variation of the following instruction while keeping the semantic meaning.\nInput: {sentence}\nOutput:"
            return await self.generate_async(prompt, temperature=temperature)
    
    async def close(self):
        """Close the aiohttp session"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    # Synchronous wrappers for compatibility
    def generate(self, prompt: str, **kwargs) -> str:
        """Synchronous wrapper for generate_async"""
        return asyncio.run(self.generate_async(prompt, **kwargs))
    
    def batch_generate(self, prompts: List[str], **kwargs) -> List[str]:
        """Synchronous wrapper for batch_generate_async"""
        return asyncio.run(self.batch_generate_async(prompts, **kwargs))
    
    def paraphrase(self, sentence: Union[str, List[str]], temperature: float = 0.7) -> Union[str, List[str]]:
        """Synchronous wrapper for paraphrase_async"""
        return asyncio.run(self.paraphrase_async(sentence, temperature))


# Factory function for creating async clients
def create_async_client(max_concurrency: int = 16, **kwargs) -> AsyncLLMClient:
    """Create an async LLM client with specified concurrency."""
    return AsyncLLMClient(max_concurrency=max_concurrency, **kwargs)


# SVEN-style compatibility functions for async
async def sven_llm_query_async(
    data: Union[str, List[str]], 
    client: AsyncLLMClient, 
    task: bool = False, 
    temperature: float = 0.1, 
    **kwargs
) -> Union[str, List[str]]:
    """
    Async version of SVEN-style LLM query function.
    
    Args:
        data: Single prompt or list of prompts
        client: Async LLM client
        task: Whether task-oriented (will truncate multi-paragraph responses)
        temperature: Temperature parameter
        **kwargs: Other parameters
    
    Returns:
        Single response or list of responses
    """
    kwargs.update({"task": task, "temperature": temperature})
    
    if isinstance(data, list):
        return await client.batch_generate_async(data, **kwargs)
    else:
        return await client.generate_async(data, **kwargs)


def sven_llm_query_sync(
    data: Union[str, List[str]], 
    max_concurrency: int = 16,
    batch_size: int = 8,
    task: bool = False, 
    temperature: float = 0.1, 
    **kwargs
) -> Union[str, List[str]]:
    """
    Synchronous SVEN-style query with async performance benefits.
    Creates temporary async client for the request.
    """
    async def _async_query():
        async with create_async_client(max_concurrency=max_concurrency) as client:
            return await sven_llm_query_async(data, client, task, temperature, **kwargs)
    
    return asyncio.run(_async_query())