from sentinel.profiles.base import BaseProfile
from sentinel.profiles.default import DefaultProfile
from sentinel.profiles.fast import FastProfile


class ProfileRegistry:
    def create(
        self,
        name: str,
    ) -> BaseProfile:

        """ Vous pouvez définir d'autre profils et les ajouter."""
        profiles: dict[str, type[BaseProfile]] = {
            "default": DefaultProfile,
            "fast": FastProfile,
        }

        try:
            profile_class = profiles[name]
        except KeyError:
            raise ValueError(f"Unknown scan profile: {name}") from None

        return profile_class()
