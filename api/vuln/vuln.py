# -*- coding: utf-8 -*-
# @name: vuln
# @description: 漏洞管理API - 简化版漏洞信息管理
# @author: Assistant
# @version: 2.0

from typing import Optional, List
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorCursor
from pymongo import DESCENDING
from pydantic import BaseModel, Field
from api.users import verify_token
from core.db import get_mongo_db
from core.util import get_now_time
from loguru import logger

router = APIRouter()


# 数据模型定义
class VulnerabilityInfo(BaseModel):
    """漏洞信息模型 - 简化版只包含核心字段"""
    name: Optional[str] = Field(None, description="漏洞名称")
    description: Optional[str] = Field(None, description="漏洞描述")
    level: Optional[str] = Field("info", description="漏洞等级: critical, high, medium, low, info")
    classification: Optional[str] = Field(None, description="漏洞分类")
    vul_status: Optional[bool] = Field(True, description="漏洞状态")


class VulnerabilityResponse(BaseModel):
    """漏洞响应模型"""
    id: str
    name: str
    description: str
    level: str
    classification: str
    vul_status: bool


class PocRespData(BaseModel):
    """POC响应数据模型"""
    message: str
    code: int


# API实现

@router.get("")
async def get_vulnerability_list(
    page: int = Query(1, ge=1, description="页码"),
    size: int = Query(10, ge=1, le=100, description="每页数量"),
    search: Optional[str] = Query(None, description="搜索关键词"),
    level: Optional[str] = Query(None, description="漏洞等级"),
    vul_status: Optional[bool] = Query(None, description="漏洞状态"),
    classification: Optional[str] = Query(None, description="漏洞分类"),
    db=Depends(get_mongo_db),
    _: dict = Depends(verify_token)
):
    """获取漏洞列表，支持分页和过滤"""
    try:
        # 构建查询条件
        query = {}
        
        if search:
            query["$or"] = [
                {"name": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}}
            ]
        
        if level:
            query["level"] = level
            
        if vul_status is not None:
            query["vul_status"] = vul_status
            
        if classification:
            query["classification"] = classification

        # 获取总数
        total_count = await db.vul_template.count_documents(query)
        
        if total_count == 0:
            return {
                "code": 200,
                "data": {
                    "list": [],
                    "total": 0,
                    "page": page,
                    "size": size
                }
            }

        # 分页查询
        skip = (page - 1) * size
        cursor: AsyncIOMotorCursor = db.vul_template.find(query)\
            .sort([("_id", DESCENDING)])\
            .skip(skip)\
            .limit(size)
        
        results = await cursor.to_list(length=None)
        
        # 格式化返回数据
        vulnerabilities = []
        for doc in results:
            vulnerability = {
                "id": str(doc["_id"]),
                "name": doc.get("name", ""),
                "description": doc.get("description", ""),
                "level": doc.get("level", "info"),
                "classification": doc.get("classification", ""),
                "vul_status": doc.get("vul_status", True)
            }
            vulnerabilities.append(vulnerability)

        return {
            "code": 200,
            "data": {
                "list": vulnerabilities,
                "total": total_count,
                "page": page,
                "size": size
            }
        }

    except Exception as e:
        logger.error(f"获取漏洞列表失败: {str(e)}")
        return {"message": "获取漏洞列表失败", "code": 500}


@router.get("/search")
async def search_vulnerability_by_name(
    name: str = Query(..., description="漏洞名称"),
    db=Depends(get_mongo_db),
    _: dict = Depends(verify_token)
):
    """通过漏洞名称搜索漏洞"""
    try:
        query = {"name": {"$regex": name, "$options": "i"}}
        
        docs = await db.vul_template.find(query)\
            .sort([("_id", DESCENDING)])\
            .to_list(length=100)
        
        vulnerabilities = []
        for doc in docs:
            vulnerability = {
                "id": str(doc["_id"]),
                "name": doc.get("name", ""),
                "description": doc.get("description", ""),
                "level": doc.get("level", "info"),
                "classification": doc.get("classification", ""),
                "vul_status": doc.get("vul_status", True)
            }
            vulnerabilities.append(vulnerability)

        return {
            "code": 200,
            "data": {
                "data": vulnerabilities
            }
        }

    except Exception as e:
        logger.error(f"搜索漏洞失败: {str(e)}")
        return {"message": "搜索漏洞失败", "code": 500}


@router.post("")
async def create_vulnerability(
    vulnerability_data: dict,
    db=Depends(get_mongo_db),
    _: dict = Depends(verify_token)
):
    """新增漏洞信息"""
    try:
        # 构建漏洞文档 - 只包含核心字段
        doc = {
            "name": vulnerability_data.get("name", ""),
            "description": vulnerability_data.get("description", ""),
            "level": vulnerability_data.get("level", "info"),
            "classification": vulnerability_data.get("classification", ""),
            "vul_status": vulnerability_data.get("vul_status", True)
        }

        # 检查漏洞名称是否已存在
        existing_vuln = await db.vul_template.find_one({"name": doc["name"]})
        if existing_vuln:
            return {"message": "漏洞名称已存在", "code": 400}

        result = await db.vul_template.insert_one(doc)
        
        if result.inserted_id:
            return {
                "code": 200,
                "message": "漏洞新增成功",
                "data": {
                    "id": str(result.inserted_id)
                }
            }
        else:
            return {"message": "漏洞新增失败", "code": 500}

    except Exception as e:
        logger.error(f"新增漏洞失败: {str(e)}")
        return {"message": "新增漏洞失败", "code": 500}


@router.put("/{vulnerability_id}")
async def update_vulnerability(
    vulnerability_id: str,
    vulnerability_data: dict,
    db=Depends(get_mongo_db),
    _: dict = Depends(verify_token)
):
    """更新漏洞信息"""
    try:
        if not ObjectId.is_valid(vulnerability_id):
            return {"message": "无效的漏洞ID", "code": 400}

        # 检查漏洞是否存在
        existing_doc = await db.vul_template.find_one({"_id": ObjectId(vulnerability_id)})
        if not existing_doc:
            return {"message": "漏洞不存在", "code": 404}

        # 如果更新名称，检查名称是否已被其他漏洞使用
        new_name = vulnerability_data.get("name")
        if new_name and new_name != existing_doc.get("name"):
            name_exists = await db.vul_template.find_one({
                "name": new_name,
                "_id": {"$ne": ObjectId(vulnerability_id)}
            })
            if name_exists:
                return {"message": "漏洞名称已存在", "code": 400}

        # 构建更新数据 - 只允许更新核心字段
        update_doc = {"$set": {}}
        
        allowed_fields = ["name", "description", "level", "classification", "vul_status"]
        
        for field in allowed_fields:
            if field in vulnerability_data:
                update_doc["$set"][field] = vulnerability_data[field]

        if update_doc["$set"]:
            result = await db.vul_template.update_one(
                {"_id": ObjectId(vulnerability_id)},
                update_doc
            )
            
            if result.modified_count > 0:
                return {
                    "code": 200,
                    "message": "漏洞更新成功"
                }
            else:
                return {"message": "没有内容需要更新", "code": 200}
        else:
            return {"message": "没有提供更新数据", "code": 400}

    except Exception as e:
        logger.error(f"更新漏洞失败: {str(e)}")
        return {"message": "更新漏洞失败", "code": 500}


@router.delete("")
async def delete_vulnerabilities(
    request_data: dict,
    db=Depends(get_mongo_db),
    _: dict = Depends(verify_token)
):
    """批量删除漏洞"""
    try:
        ids = request_data.get("ids", [])
        
        if not ids:
            return {"message": "请提供要删除的漏洞ID列表", "code": 400}

        # 验证所有ID格式
        object_ids = []
        for id_str in ids:
            if not ObjectId.is_valid(id_str):
                return {"message": f"无效的漏洞ID: {id_str}", "code": 400}
            object_ids.append(ObjectId(id_str))

        result = await db.vul_template.delete_many({"_id": {"$in": object_ids}})
        
        return {
            "code": 200,
            "message": f"成功删除 {result.deleted_count} 个漏洞"
        }

    except Exception as e:
        logger.error(f"删除漏洞失败: {str(e)}")
        return {"message": "删除漏洞失败", "code": 500}


@router.put("/{vulnerability_id}/status")
async def update_vulnerability_status(
    vulnerability_id: str,
    request_data: dict,
    db=Depends(get_mongo_db),
    _: dict = Depends(verify_token)
):
    """更新漏洞状态"""
    try:
        if not ObjectId.is_valid(vulnerability_id):
            return {"message": "无效的漏洞ID", "code": 400}

        vul_status = request_data.get("vul_status")
        if vul_status is None:
            return {"message": "请提供漏洞状态", "code": 400}

        result = await db.vul_template.update_one(
            {"_id": ObjectId(vulnerability_id)},
            {"$set": {"vul_status": vul_status}}
        )
        
        if result.matched_count == 0:
            return {"message": "漏洞不存在", "code": 404}
        
        if result.modified_count > 0:
            return {
                "code": 200,
                "message": "漏洞状态更新成功"
            }
        else:
            return {"message": "漏洞状态无需更新", "code": 200}

    except Exception as e:
        logger.error(f"更新漏洞状态失败: {str(e)}")
        return {"message": "更新漏洞状态失败", "code": 500}


@router.put("/{vulnerability_id}/poc")
async def update_poc_content(
    vulnerability_id: str,
    request_data: dict,
    db=Depends(get_mongo_db),
    _: dict = Depends(verify_token)
):
    """更新漏洞的POC内容 - 简化版本，暂不支持POC字段"""
    try:
        return {"message": "简化版本暂不支持POC内容管理", "code": 501}

    except Exception as e:
        logger.error(f"更新POC内容失败: {str(e)}")
        return {"message": "更新POC内容失败", "code": 500}


# 统计相关API
@router.get("/statistics/summary")
async def get_vulnerability_statistics(
    db=Depends(get_mongo_db),
    _: dict = Depends(verify_token)
):
    """获取漏洞统计信息"""
    try:
        # 总漏洞数
        total_count = await db.vul_template.count_documents({})
        
        # 按等级统计
        level_pipeline = [
            {"$group": {"_id": "$level", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]
        level_stats = await db.vul_template.aggregate(level_pipeline).to_list(None)
        
        # 按状态统计
        status_pipeline = [
            {"$group": {"_id": "$vul_status", "count": {"$sum": 1}}}
        ]
        status_stats = await db.vul_template.aggregate(status_pipeline).to_list(None)
        
        # 按分类统计 - 过滤空分类
        classification_pipeline = [
            {"$match": {"classification": {"$ne": None, "$ne": ""}}},
            {"$group": {"_id": "$classification", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        classification_stats = await db.vul_template.aggregate(classification_pipeline).to_list(None)

        return {
            "code": 200,
            "data": {
                "total": total_count,
                "level_stats": level_stats,
                "status_stats": status_stats,
                "classification_stats": classification_stats
            }
        }

    except Exception as e:
        logger.error(f"获取漏洞统计失败: {str(e)}")
        return {"message": "获取漏洞统计失败", "code": 500}
