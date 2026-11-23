"""pytest 根配置：把仓库根目录加入 sys.path，便于导入 hook 包。"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
