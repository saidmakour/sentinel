from typing import Any

JsonObject = dict[str, Any]
JsonArray = list[object]

TomlValue = str | int | float | bool | None | dict[str, Any] | list[Any]
