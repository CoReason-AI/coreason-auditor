from typing import Dict, List, Optional

from pydantic import BaseModel

from coreason_identity.types import SecretStr


class UserContext(BaseModel):
    user_id: SecretStr
    roles: List[str]
    metadata: Optional[Dict[str, str]] = None
