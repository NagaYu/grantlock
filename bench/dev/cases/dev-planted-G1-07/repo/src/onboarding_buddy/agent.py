import os

from anthropic import Anthropic


def client() -> Anthropic:
    # key comes from the environment, never from source
    return Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
