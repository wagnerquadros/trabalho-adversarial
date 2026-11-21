"""Check the local Ollama server and report whether Qwen returned thinking content."""

import os

from ollama import Client


OLLAMA_HOST = os.getenv(
    "OLLAMA_HOST", "http://localhost:11434"
)
MODEL_ID = "qwen3:8b"


def main() -> None:
    """Send one request using the same model and sampling settings as the smoke run."""
    client = Client(
        host=OLLAMA_HOST,
        timeout=120,
    )

    print(f"Servidor: {OLLAMA_HOST}")
    print(f"Modelo: {MODEL_ID}")
    print("Enviando mensagem...\n")

    # The SDK overload includes a partially typed optional tool callback.
    response = client.chat(  # pyright: ignore[reportUnknownMemberType]
        model=MODEL_ID,
        messages=[
            {
                "role": "user",
                "content": "Responda somente: conexão funcionando.",
            }
        ],
        think=True,
        options={
            "temperature": 0,
            "seed": 0,
        },
    )

    print("Resposta:", response.message.content)
    print("Thinking:", bool(response.message.thinking))


if __name__ == "__main__":
    main()
