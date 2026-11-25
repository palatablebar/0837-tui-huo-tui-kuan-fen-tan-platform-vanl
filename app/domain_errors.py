"""领域异常基类。

刻意不依赖 Flask 等任何 Web 框架：离线核验工具（``tools/verify_receipt.py``）
与气隙环境只需要领域层与加密原语，不能被 Web 依赖拖住。
"""


class DomainIssue(Exception):
    def __init__(self, code: str, status: int = 400, detail: str | None = None):
        self.code = code
        self.status = status
        self.detail = detail
        super().__init__(code)
