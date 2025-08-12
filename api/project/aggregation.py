# -------------------------------------
# @file      : aggregation.py
# @author    : Autumn
# @contact   : rainy-autumn@outlook.com
# @time      : 2024/7/8 21:02
# @moved     : 移动到api/project目录并重命名
# -------------------------------------------
import asyncio
import copy
import time
import traceback

from bson import ObjectId
from fastapi import APIRouter, Depends, BackgroundTasks
from pymongo import DESCENDING

from api.users import verify_token
from motor.motor_asyncio import AsyncIOMotorCursor

from core.config import Project_List
from core.db import get_mongo_db
from core.redis_handler import refresh_config, get_redis_pool
from loguru import logger
from core.util import *
from api.task.handler import scheduler

router = APIRouter()


@router.post("/project/info")
async def get_projects_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    id = request_data.get("id", "")
    result = await db.project.find_one({"_id": ObjectId(id)}, {
        "_id": 0,
        "tag": 1,
        "hour": 1,
        "scheduledTasks": 1,
        "AssetCount": 1,
        "root_domains": 1,
        "name": 1
    }
                                       )
    if result['scheduledTasks']:
        job = scheduler.get_job(id)
        if job is not None:
            next_time = job.next_run_time.strftime("%Y-%m-%d %H:%M:%S")
            result['next_time'] = next_time
    return {"code": 200, "data": result}


@router.post("/project/asset/count")
async def get_projects_asset_count(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    id = request_data.get("id", "")
    subdomain_count = await db['subdomain'].count_documents({"project": id})
    vulnerability_count = await db['vulnerability'].count_documents({"project": id})
    return {"code": 200, "data": {
        "subdomainCount": subdomain_count,
        "vulCount": vulnerability_count
    }}


@router.post("/project/vul/statistics")
async def get_projects_vul_statistics(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    id = request_data.get("id", "")
    pipeline = [
        {"$match": {"project": id}},
        {
            "$group": {
                "_id": "$level",
                "count": {"$sum": 1}
            }
        }
    ]
    result = await db['vulnerability'].aggregate(pipeline).to_list(None)
    return {"code": 200, "data": result}


@router.post("/project/vul/data")
async def get_projects_vul_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    id = request_data.get("id", "")
    pipeline = [
        {"$match": {"project": id}},
        {"$group": {
            "_id": "$vulname",
            "count": {"$sum": 1},
            "level": {"$first": "$level"},  # 保留第一个级别
            "children": {
                "$push": {
                    "url": "$url",
                    "vulname": "$vulname",
                    "level": "$level",
                    "time": "$time",
                    "matched": "$matched",
                    "id": {"$toString": "$_id"}
                }
            }
        }},
        # 首先按照level排序（高危优先），然后按照count排序
        {"$sort": {
            "level": -1,  # level降序（高危优先）
            "count": -1   # count降序
        }},
        {"$project": {
            "_id": 0,
            "vulname": "$_id",
            "count": 1,
            "level": 1,
            "id": {"$function": {
                "body": "function() { return Math.random().toString(36).substring(7); }",
                "args": [],
                "lang": "js"
            }},
            "children": {"$slice": ["$children", 10]}  # 限制每组最多显示10条记录
        }}
    ]

    result = await db.vulnerability.aggregate(pipeline).to_list(None)
    return {
        "code": 200,
        "data": {
            'list': result
        }
    }


async def process_domains(root_domains, query, db):
    """优化后的域名处理函数"""
    # 使用 $or 和简单的字符串匹配来处理域名
    domain_conditions = []
    batch_size = 10  # 每批处理的域名数量
    
    # 分批处理域名以避免正则表达式过长
    for i in range(0, len(root_domains), batch_size):
        batch_domains = root_domains[i:i + batch_size]
        pattern = "|".join(f"{domain}$" for domain in batch_domains)
        domain_conditions.append({"host": {"$regex": pattern}})
    
    # 将域名条件添加到查询中
    if "$and" in query:
        query["$and"].append({"$or": domain_conditions})
    else:
        query["$or"] = domain_conditions

    # 使用索引优化的查询
    cursor = db['subdomain'].find(
        query,
        {
            "_id": 0,
            "id": {"$toString": "$_id"},
            "host": 1,
            "type": 1,
            "value": {"$ifNull": ["$value", []]},
            "ip": {"$ifNull": ["$ip", []]},
            "time": 1
        }
    ).sort([("time", -1)]).hint([("time", -1)])

    results = await cursor.to_list(None)
    
    # 优化内存处理
    domain_results = {domain: [] for domain in root_domains}
    for r in results:
        host = r.get('host', '')
        for domain in root_domains:
            if host.endswith(domain):
                domain_results[domain].append(r)
                break

    return [
        {
            "host": domain,
            "type": "",
            "value": [],
            "ip": [],
            "id": generate_random_string(5),
            "children": items,
            "count": len(items)
        }
        for domain, items in domain_results.items()
    ]


@router.post("/project/subdomain/data")
async def get_projects_subdomain_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    filter = request_data.get("filter", {})
    project_id = filter["project"][0]
    project_query = {}
    project_query["_id"] = ObjectId(project_id)
    doc = await db.project.find_one(project_query, {"_id": 0, "root_domains": 1})
    if not doc or "root_domains" not in doc:
        return {"code": 404, "message": "domain is null"}
    query = await get_search_query("subdomain", request_data)
    if query == "":
        return {"message": "Search condition parsing error", "code": 500}
    root_domains = doc["root_domains"]
    results = await process_domains(root_domains, query, db)
    return {
        "code": 200,
        "data": {
            'list': results
        }
    }


@router.post("/project/port/data")
async def get_projects_port_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    query = await get_search_query("asset", request_data)
    if query == "":
        return {"message": "Search condition parsing error", "code": 500}

    pipeline = [
        {"$match": query},
        {"$group": {
            "_id": "$port",
            "count": {"$sum": 1},
            "sample": {  # 只获取最新的10个样本
                "$push": {
                    "$cond": [
                        {"$lt": [{"$size": {"$ifNull": ["$sample", []]}}, 10]},
                        {
                            "service": "$service",
                            "host": "$host",
                            "time": "$time",
                            "ip": "$ip",
                            "id": {"$toString": "$_id"}
                        },
                        "$$REMOVE"
                    ]
                }
            }
        }},
        {"$sort": {"count": -1}},
        {"$project": {
            "_id": 0,
            "port": "$_id",
            "count": 1,
            "id": {"$function": {
                "body": "function() { return Math.random().toString(36).substring(7); }",
                "args": [],
                "lang": "js"
            }},
            "children": "$sample"
        }}
    ]

    # 使用hint强制使用port索引
    result = await db['asset'].aggregate(pipeline, hint={"port": 1}).to_list(None)
    return {"code": 200, "data": {'list': result}}


@router.post("/project/service/data")
async def get_projects_service_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    query = await get_search_query("asset", request_data)
    if query == "":
        return {"message": "Search condition parsing error", "code": 500}

    pipeline = [
        {"$match": query},
        {"$group": {
            "_id": {"$ifNull": ["$service", "unknown"]},
            "count": {"$sum": 1},
            "sample": {  # 只获取最新的10个样本
                "$push": {
                    "$cond": [
                        {"$lt": [{"$size": {"$ifNull": ["$sample", []]}}, 10]},
                        {
                            "service": {"$ifNull": ["$webServer", ""]},
                            "host": "$host",
                            "ip": "$ip",
                            "time": "$time",
                            "port": "$port",
                            "id": {"$toString": "$_id"}
                        },
                        "$$REMOVE"
                    ]
                }
            }
        }},
        {"$sort": {"count": -1}},
        {"$project": {
            "_id": 0,
            "service": "$_id",
            "count": 1,
            "id": {"$function": {
                "body": "function() { return Math.random().toString(36).substring(7); }",
                "args": [],
                "lang": "js"
            }},
            "host": "",
            "ip": "",
            "time": "",
            "port": "",
            "children": "$sample"
        }}
    ]

    # 使用hint强制使用service索引
    result = await db['asset'].aggregate(pipeline, hint={"service": 1}).to_list(None)
    return {"code": 200, "data": {'list': result}}
