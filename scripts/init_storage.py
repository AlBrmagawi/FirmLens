import os
from pathlib import Path

for directory, uid in [("/data", 10001), ("/intelligence", 65532), ("/exports", 10001)]:
    path = Path(directory)
    path.mkdir(exist_ok=True)
    os.chown(path, uid, uid)
    path.chmod(0o700)
    # Prevent Docker copy-up from replacing ownership of an empty named volume.
    marker = path / ".firmwarelens-volume"
    marker.touch(exist_ok=True)
    os.chown(marker, uid, uid)
