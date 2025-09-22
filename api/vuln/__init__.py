# -*- coding: utf-8 -*-
# @name: __init__.py
# @description: 漏洞管理模块初始化文件
# @author: Assistant
# @version: 1.0

from fastapi import APIRouter
from .vuln import router as vuln_router

router = APIRouter()

# 包含漏洞管理路由
router.include_router(vuln_router, prefix="/vulnerabilities")
