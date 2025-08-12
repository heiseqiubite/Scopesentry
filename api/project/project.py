import time
import traceback
import asyncio
from typing import List
from bson import ObjectId
from fastapi import APIRouter, Depends, BackgroundTasks, File, UploadFile, Form

from api.project.handler import (
    update_project, 
    delete_asset_project_handler, 
    parse_uploaded_file, 
    process_scan_results,
    update_project_count,
    process_project_target_list
)
from api.task.handler import (
    scheduler_scan_task, 
    insert_task, 
    scheduler,
    handle_project_scheduler_task,
    remove_project_scheduler_task,
    update_project_scheduler_task,
    run_project_task_now,
    get_before_last_dash
)
from api.task.util import delete_asset, get_target_list
from api.users import verify_token
from core.db import get_mongo_db
from core.redis_handler import refresh_config, get_redis_pool
from core.util import *

router = APIRouter()


@router.post("/data")
async def get_projects_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token),
                            background_tasks: BackgroundTasks = BackgroundTasks()):
    background_tasks.add_task(update_project_count)
    search_query = request_data.get("search", "")
    page_index = request_data.get("pageIndex", 1)
    page_size = request_data.get("pageSize", 10)

    query = {
        "$or": [
            {"name": {"$regex": search_query, "$options": "i"}},
            {"root_domain": {"$regex": search_query, "$options": "i"}}
        ]
    } if search_query else {}

    # 获取标签统计信息
    tag_result = await db.project.aggregate([
        {"$group": {"_id": "$tag", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]).to_list(None)

    tag_num = {tag["_id"]: tag["count"] for tag in tag_result}
    all_num = sum(tag_num.values())
    tag_num["All"] = all_num

    result_list = {}

    async def fetch_projects(tag, tag_query):
        cursor = db.project.find(tag_query, {
            "_id": 0,
            "id": {"$toString": "$_id"},
            "name": 1,
            "logo": 1,
            "AssetCount": 1,
            "tag": 1
        }).sort("AssetCount", -1).skip((page_index - 1) * page_size).limit(page_size)

        results = await cursor.to_list(length=None)
        for result in results:
            result["AssetCount"] = result.get("AssetCount", 0)
        return results

    fetch_tasks = []
    for tag in tag_num:
        if tag != "All":
            tag_query = {"$and": [query, {"tag": tag}]}
        else:
            tag_query = query

        fetch_tasks.append(fetch_projects(tag, tag_query))

    fetch_results = await asyncio.gather(*fetch_tasks)

    for tag, results in zip(tag_num, fetch_results):
        result_list[tag] = results

    return {
        "code": 200,
        "data": {
            "result": result_list,
            "tag": tag_num
        }
    }


@router.get("/all")
async def get_projects_all(db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    try:
        pipeline = [
            {
                "$group": {
                    "_id": "$tag",  # 根据 tag 字段分组
                    "children": {"$push": {"value": {"$toString": "$_id"}, "label": "$name"}}  # 将每个文档的 _id 和 name 放入 children 集合中
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "label": "$_id",
                    "value": {"$literal": ""},
                    "children": 1
                }
            }
        ]
        result = await db['project'].aggregate(pipeline).to_list(None)
        return {
            "code": 200,
            "data": {
                'list': result
            }
        }
    except Exception as e:
        logger.error(str(e))
        logger.error(traceback.format_exc())
        return {"message": "error","code":500}


@router.post("/content")
async def get_project_content(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token)):
    project_id = request_data.get("id")
    if not project_id:
        return {"message": "ID is missing in the request data", "code": 400}
    query = {"_id": ObjectId(project_id)}
    doc = await db.project.find_one(query)
    if not doc:
        return {"message": "Content not found for the provided ID", "code": 404}
    project_target_data = await db.ProjectTargetData.find_one({"id": project_id})
    result = {
        "name": doc.get("name", ""),
        "tag": doc.get("tag", ""),
        "target": project_target_data.get("target", ""),
        "node": doc.get("node", []),
        "logo": doc.get("logo", ""),
        "scheduledTasks": doc.get("scheduledTasks"),
        "hour": doc.get("hour"),
        "allNode": doc.get("allNode", False),
        "duplicates": doc.get("duplicates"),
        "template": doc.get("template"),
        "ignore": doc.get("ignore"),
    }
    return {"code": 200, "data": result}

# get_before_last_dash函数已移动到api.task.project_handler模块


@router.post("/add")
async def add_project_rule(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token),
                           background_tasks: BackgroundTasks = BackgroundTasks()):
    # Extract values from request data
    name = request_data.get("name")
    cursor = db.project.find({"name": {"$eq": name}}, {"_id": 1})
    results = await cursor.to_list(length=None)
    if len(results) != 0:
        return {"code": 400, "message": "name already exists"}
    target = request_data.get("target").strip("\n").strip("\r").strip()
    runNow = request_data.get("runNow")
    request_data["tp"] = "project"
    del request_data["runNow"]
    scheduledTasks = request_data.get("scheduledTasks", False)
    hour = request_data.get("hour", 24)
    root_domains = await process_project_target_list(target, request_data.get("ignore", ""))
    request_data["root_domains"] = root_domains
    del request_data['target']
    # Insert the new document into the SensitiveRule collection
    result = await db.project.insert_one(request_data)
    # Check if the insertion was successful6
    if result.inserted_id:
        project_id = str(result.inserted_id)
        await db.ProjectTargetData.insert_one({"id": project_id, "target": target})
        
        # 处理定时任务
        if scheduledTasks:
            project_data = request_data.copy()
            project_data["target"] = target
            await handle_project_scheduler_task(project_data, project_id, scheduledTasks, hour)
        
        # 立即运行任务
        if runNow:
            project_data = request_data.copy()
            project_data["target"] = target
            if "scheduledTasks" in project_data:
                del project_data["scheduledTasks"]
            await run_project_task_now(project_data, project_id)
        background_tasks.add_task(update_project, root_domains, str(result.inserted_id), False)
        await refresh_config('all', 'project', str(result.inserted_id))
        # Project_List[name] = str(result.inserted_id)
        Project_List[str(result.inserted_id)] = name
        return {"code": 200, "message": "Project added successfully"}
    else:
        return {"code": 400, "message": "Failed to add Project"}


@router.post("/delete")
async def delete_project_rules(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token),
                               background_tasks: BackgroundTasks = BackgroundTasks()):
    try:
        pro_ids = request_data.get("ids", [])
        delA = request_data.get("delA", False)
        if delA:
            background_tasks.add_task(delete_asset, pro_ids, True)
        obj_ids = [ObjectId(poc_id) for poc_id in pro_ids]
        result = await db.project.delete_many({"_id": {"$in": obj_ids}})
        await db.ProjectTargetData.delete_many({"id": {"$in": pro_ids}})
        # Check if the deletion was successful
        if result.deleted_count > 0:
            for pro_id in pro_ids:
                # 移除定时任务
                await remove_project_scheduler_task(pro_id)
                background_tasks.add_task(delete_asset_project_handler, pro_id)
                if pro_id in Project_List:
                    del Project_List[pro_id]
            return {"code": 200, "message": "Project deleted successfully"}
        else:
            return {"code": 404, "message": "Project not found"}

    except Exception as e:
        logger.error(str(e))
        # Handle exceptions as needed
        return {"message": "error", "code": 500}


@router.post("/update")
async def update_project_data(request_data: dict, db=Depends(get_mongo_db), _: dict = Depends(verify_token),
                              background_tasks: BackgroundTasks = BackgroundTasks()):
    try:
        # Get the ID from the request data
        pro_id = request_data.get("id")
        hour = request_data.get("hour")
        runNow = request_data.get("runNow")
        del request_data["runNow"]
        if not pro_id:
            return {"message": "ID is missing in the request data", "code": 400}
        scheduledTasks = request_data.get("scheduledTasks")
        target = request_data.get("target").strip("\n").strip("\r").strip()
        # 更新目标记录
        await db.ProjectTargetData.update_one({"id": pro_id}, {"$set": {"target": target}})
        root_domains = await process_project_target_list(target, request_data.get("ignore", ""))
        request_data["root_domains"] = root_domains
        request_data.pop("id")
        del request_data['target']
        update_document = {
            "$set": request_data
        }
        await db.project.update_one({"_id": ObjectId(pro_id)}, update_document)
        
        # 更新定时任务
        project_data = request_data.copy()
        project_data["target"] = target
        await update_project_scheduler_task(project_data, pro_id, scheduledTasks, hour)
        
        # 立即运行任务
        if runNow:
            project_data = request_data.copy()
            project_data["target"] = target
            if "scheduledTasks" in project_data:
                del project_data["scheduledTasks"]
            await run_project_task_now(project_data, pro_id)
        background_tasks.add_task(update_project, root_domains, pro_id, True)
        await refresh_config('all', 'project', pro_id)
        # Project_List[request_data.get("name")] = pro_id
        Project_List[pro_id] = request_data.get("name")
        return {"code": 200, "message": "successfully"}
    except Exception as e:
        logger.error(str(e))
        logger.error(traceback.format_exc())
        # Handle exceptions as needed
        return {"message": "error", "code": 500}


@router.post("/upload")
async def upload_and_parse_files(
    files: List[UploadFile] = File(...), 
    id: str = Form(...),
    db=Depends(get_mongo_db), 
    _: dict = Depends(verify_token), 
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """批量上传并解析扫描结果文件（支持.json, .dat格式）"""
    try:
        # 验证项目是否存在
        project = await db.project.find_one({"_id": ObjectId(id)})
        if not project:
            return {"code": 404, "message": "项目不存在"}
        
        if not files:
            return {"code": 400, "message": "未选择文件"}
        
        project_name = project.get("name", "")
        total_results_count = 0
        processed_files = []
        failed_files = []
        
        # 处理每个文件
        for file in files:
            try:
                # 读取并解析文件
                content = await file.read()
                parsed_results = await parse_uploaded_file(content, file.filename)
                
                if not parsed_results:
                    failed_files.append({
                        "filename": file.filename,
                        "error": "文件解析失败或文件为空"
                    })
                    continue
                
                # 计算结果数量
                results_count = len(parsed_results) - 1 if len(parsed_results) > 1 else 0
                total_results_count += results_count
                
                # 后台处理数据
                background_tasks.add_task(
                    process_scan_results,
                    parsed_results,
                    id,
                    project_name,
                    file.filename
                )
                
                processed_files.append({
                    "filename": file.filename,
                    "file_size": file.size,
                    "results_count": results_count
                })
                
            except Exception as file_error:
                logger.error(f"处理文件 {file.filename} 错误: {str(file_error)}")
                failed_files.append({
                    "filename": file.filename,
                    "error": str(file_error)
                })
        
        # 准备响应消息
        success_count = len(processed_files)
        failed_count = len(failed_files)
        
        if success_count > 0 and failed_count == 0:
            message = f"成功上传 {success_count} 个文件，发现 {total_results_count} 条结果，正在后台处理"
        elif success_count > 0 and failed_count > 0:
            message = f"成功上传 {success_count} 个文件，{failed_count} 个文件处理失败，发现 {total_results_count} 条结果，正在后台处理"
        else:
            message = f"所有 {failed_count} 个文件处理失败"
        
        return {
            "code": 200 if success_count > 0 else 400,
            "message": message,
            "data": {
                "project_id": id,
                "total_files": len(files),
                "success_count": success_count,
                "failed_count": failed_count,
                "total_results_count": total_results_count,
                "processed_files": processed_files,
                "failed_files": failed_files
            }
        }
        
    except Exception as e:
        logger.error(f"批量上传文件错误: {str(e)}")
        logger.error(traceback.format_exc())
        return {"code": 500, "message": f"上传失败: {str(e)}"}


