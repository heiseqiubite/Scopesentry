# -------------------------------------
# @file      : asset.py
# @author    : Autumn
# @contact   : rainy-autumn@outlook.com
# @time      : 2024/10/20 20:52
# -------------------------------------------
import json
import traceback

from bson import ObjectId
from fastapi import APIRouter, Depends
from api.users import verify_token
from motor.motor_asyncio import AsyncIOMotorCursor

from core.db import get_mongo_db
from core.util import *
from pymongo import DESCENDING
from loguru import logger
router = APIRouter()


@router.post("/data")
async def asset_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    try:
        page_index = request_data.get("pageIndex", 1)
        page_size = request_data.get("pageSize", 10)
        query = await get_search_query("asset", request_data)
        if query == "":
            return {"message": "Search condition parsing error", "code": 500}

        # 只查询需要的字段，减少数据传输量
        projection = {
            "_id": 1,
            "ip": 1,
            "port": 1,
            "time": 1,
            "type": 1,
            "host": 1,
            "service": 1,
            "tags": 1,
            "technologies": 1,
            "metadata": 1,
            "title": 1,
            "statuscode": 1,
            "url": 1,
            "screenshot": 1,
            "rawheaders": 1,
            "iconcontent": 1
        }

        cursor: AsyncIOMotorCursor = db['asset'].find(
            query,
            projection
        ).skip((page_index - 1) * page_size).limit(page_size).sort([("time", DESCENDING)])
        
        result_list = []
        async for r in cursor:
            # 预处理基础字段
            tmp = {
                'id': str(r['_id']),
                'ip': r['ip'],
                'port': r['port'],
                'time': r['time'],
                'type': r['type'],
                'domain': r['host'],
                'service': r['service'],
                'tags': r.get("tags") or [],
                'products': r.get('technologies') or []
            }

            # 根据类型处理特定字段
            if r['type'] == 'tcp':
                tmp.update({
                    'title': "",
                    'status': None,
                    'banner': "",
                    'screenshot': "",
                    'url': "",
                    'icon': ""
                })
                
                # 处理metadata
                if metadata := r.get('metadata'):
                    try:
                        raw_data = json.loads(metadata.decode('utf-8'))
                        tmp['banner'] = "\n".join(f"{k}:{str(raw_data[k]).strip()}" for k in raw_data)
                    except:
                        try:
                            tmp['banner'] = metadata.decode('utf-8')
                        except:
                            pass
            else:
                tmp.update({
                    'screenshot': r.get("screenshot", ""),
                    'title': r.get('title', ""),
                    'status': r.get('statuscode'),
                    'url': r.get('url', ""),
                    'banner': r.get('rawheaders', ""),
                    'icon': r.get('iconcontent', "")
                })
            
            result_list.append(tmp)

        return {
            "code": 200,
            "data": {
                'list': result_list,
            }
        }
    except Exception as e:
        logger.error(str(e))
        logger.error(traceback.format_exc())
        return {"message": "error", "code": 500}


@router.post("/data/card")
async def asset_card_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    try:
        page_index = request_data.get("pageIndex", 1)
        page_size = request_data.get("pageSize", 10)
        query = await get_search_query("asset", request_data)
        if query == "":
            return {"message": "Search condition parsing error", "code": 500}
        total_count = await db['asset'].count_documents(query)
        cursor: AsyncIOMotorCursor = db['asset'].find(query, {"_id": 0,
                                          "host": 1,
                                          "url": 1,
                                          "port": 1,
                                          "service": 1,
                                          "type": 1,
                                          "title": 1,
                                          "statuscode": 1,
                                          "screenshot": 1,
                                          }).skip((page_index - 1) * page_size).limit(page_size).sort(
            [("time", DESCENDING)])
        result = await cursor.to_list(length=None)
        return {
            "code": 200,
            "data": {
                'list': result,
                'total': total_count
            }
        }
    except Exception as e:
        logger.error(str(e))
        logger.error(traceback.format_exc())
        # Handle exceptions as needed
        return {"message": "error", "code": 500}

@router.post("/screenshot")
async def asset_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    id = request_data.get("id", "")
    if id == "":
        return {"message": "not found", "code": 404}
    query = {"_id": ObjectId(id)}
    doc = await db.asset.find_one(query, {"screenshot": 1})
    if doc is None:
        return {"message": "not found", "code": 404}
    screenshot = doc.get('screenshot', "")
    return {
            "code": 200,
            "data": {
                'screenshot': screenshot
            }
        }


@router.post("/detail")
async def asset_detail(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    try:
        # Get the ID from the request data
        asset_id = request_data.get("id")

        # Check if ID is provided
        if not asset_id:
            return {"message": "ID is missing in the request data", "code": 400}

        # Query the database for content based on ID
        query = {"_id": ObjectId(asset_id)}
        doc = await db.asset.find_one(query)
        doc["id"] = str(doc["_id"])
        del doc["_id"]
        return {"code": 200, "data": {"json": doc}}
    except Exception as e:
        logger.error(str(e))
        # Handle exceptions as needed
        return {"message": "error", "code": 500}


@router.post("/changelog")
async def asset_detail(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    try:
        # Get the ID from the request data
        asset_id = request_data.get("id")

        # Check if ID is provided
        if not asset_id:
            return {"message": "ID is missing in the request data", "code": 400}

        # Query the database for content based on ID
        query = {"assetid": asset_id}
        cursor: AsyncIOMotorCursor = db.AssetChangeLog.find(query).sort([("time", DESCENDING)])
        results = await cursor.to_list(length=None)
        result_list = []
        for result in results:
            del result["_id"]
            result_list.append(result)
        return {"code": 200, "data": result_list}
    except Exception as e:
        logger.error(str(e))
        # Handle exceptions as needed
        return {"message": "error", "code": 500}