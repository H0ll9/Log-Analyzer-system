# from ollamatesting import Client

# client = Client()

# messages = [
#   {
#     'role': 'user',
#     'content': 'Why is the sky blue?',
#   },
# ]

# for part in client.chat('qwen2.5-coder:7b', messages=messages, stream=True):
#   print(part.message.content, end='', flush=True)

import asyncio
from ollama import AsyncClient

async def chat():
  message = {'role': 'user', 'content': 'Why is the sky blue?'}
  async for part in await AsyncClient().chat(model='deepseek-r1:8b', messages=[message], stream=True):
    print(part['message']['content'], end='', flush=True)

asyncio.run(chat())