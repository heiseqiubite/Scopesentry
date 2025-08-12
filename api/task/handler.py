# -------------------------------------
# @file      : handlers.py
# @author    : Autumn
# @contact   : rainy-autumn@outlook.com
# @time      : 2024/10/28 22:09
# -------------------------------------------
import asyncio
import json
import re

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorCursor
from pymongo import DESCENDING
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.mongodb import MongoDBJobStore

from api.asset.page_monitoring import get_page_monitoring_data
from api.node.handler import get_node_all
from api.task.util import get_target_list
from core.config import *
from core.db import get_mongo_db
from core.redis_handler import get_redis_pool, get_redis_online_data
from core.util import get_now_time, get_search_query, get_root_domain
from loguru import logger

# =============================================================================
# 调度器管理
# =============================================================================

# MongoDB配置
mongo_config = {
    'host': MONGODB_IP,
    'port': int(MONGODB_PORT),
    'username': str(MONGODB_USER),
    'password': str(MONGODB_PASSWORD),
    'database': str(MONGODB_DATABASE),
    'collection': 'apscheduler'
}

# JobStore配置
jobstores = {
    'mongo': MongoDBJobStore(**mongo_config)
}

# 创建调度器实例
scheduler = AsyncIOScheduler(jobstores=jobstores)

def get_scheduler():
    """获取调度器实例"""
    return scheduler

def start_scheduler():
    """启动调度器"""
    if not scheduler.running:
        scheduler.start()

def shutdown_scheduler():
    """关闭调度器"""
    if scheduler.running:
        scheduler.shutdown()

def add_job(func, trigger=None, **kwargs):
    """添加任务"""
    return scheduler.add_job(func, trigger, **kwargs)

def remove_job(job_id):
    """移除任务"""
    return scheduler.remove_job(job_id)

def get_job(job_id):
    """获取任务"""
    return scheduler.get_job(job_id)

def get_jobs():
    """获取所有任务"""
    return scheduler.get_jobs()

# =============================================================================
# 核心数据处理
# =============================================================================

async def get_task_data(db, request_data, id):
    """获取任务数据模板"""
    # 获取模板数据
    template_data = await db.ScanTemplates.find_one({"_id": ObjectId(request_data["template"])})
    # 如果选择了poc 将poc参数拼接到nuclei的参数中
    if len(template_data['vullist']) != 0:
        vul_tmp = ""
        if "All Poc" in template_data['vullist']:
            vul_tmp = "*"
        else:
            for vul in template_data['vullist']:
                vul_tmp += vul + ".yaml" + ","
        vul_tmp = vul_tmp.strip(",")

        if "VulnerabilityScan" not in template_data["Parameters"]:
            template_data["Parameters"]["VulnerabilityScan"] = {"ed93b8af6b72fe54a60efdb932cf6fbc": ""}
        if "ed93b8af6b72fe54a60efdb932cf6fbc" not in template_data["Parameters"]["VulnerabilityScan"]:
            template_data["Parameters"]["VulnerabilityScan"]["ed93b8af6b72fe54a60efdb932cf6fbc"] = ""

        if "ed93b8af6b72fe54a60efdb932cf6fbc" in template_data["VulnerabilityScan"]:
            template_data["Parameters"]["VulnerabilityScan"]["ed93b8af6b72fe54a60efdb932cf6fbc"] = \
                template_data["Parameters"]["VulnerabilityScan"][
                    "ed93b8af6b72fe54a60efdb932cf6fbc"] + " -t " + vul_tmp
    # 解析参数，支持{}获取字典
    template_data["Parameters"] = await parameter_parser(template_data["Parameters"], db)
    # 删除原始的vullist
    del template_data["vullist"]
    del template_data["_id"]
    # 设置任务名称
    template_data["TaskName"] = request_data["name"]
    # 设置忽略目标
    template_data["ignore"] = request_data["ignore"]
    # 设置去重
    template_data["duplicates"] = request_data["duplicates"]
    # 任务id
    template_data["ID"] = str(id)
    # 任务类型
    template_data["type"] = request_data.get("type", "scan")
    # 是否暂停后开启
    template_data["IsStart"] = request_data.get("IsStart", False)
    return template_data

async def parameter_parser(parameter, db):
    """参数解析器"""
    dict_list = {}
    port_list = {}
    # 获取字典
    cursor: AsyncIOMotorCursor = db["dictionary"].find({})
    result = await cursor.to_list(length=None)
    for doc in result:
        dict_list[f'{doc["category"].lower()}.{doc["name"].lower()}'] = str(doc['_id'])
    # 获取端口
    cursor: AsyncIOMotorCursor = db.PortDict.find({})
    result = await cursor.to_list(length=None)
    for doc in result:
        port_list[f'{doc["name"].lower()}'] = doc["value"]

    for module_name in parameter:
        for plugin in parameter[module_name]:
            matches = re.findall(r'\{(.*?)\}', parameter[module_name][plugin])
            for match in matches:
                tp, value = match.split(".", 1)
                if tp == "dict":
                    if value.lower() in dict_list:
                        real_param = dict_list[value.lower()]
                    else:
                        real_param = match
                        logger.error(f"parameter error:module {module_name} plugin {plugin}  parameter {parameter[module_name][plugin]}")
                    parameter[module_name][plugin] = parameter[module_name][plugin].replace("{" + match + "}", real_param)
                elif tp == "port":
                    if value.lower() in port_list:
                        real_param = port_list[value.lower()]
                    else:
                        real_param = match
                        logger.error(
                            f"parameter error:module {module_name} plugin {plugin}  parameter {parameter[module_name][plugin]}")
                    parameter[module_name][plugin] = parameter[module_name][plugin].replace("{" + match + "}", real_param)
    return parameter

# =============================================================================
# 任务处理逻辑
# =============================================================================

running_tasks = set()

async def insert_task(request_data, db):
    """插入任务"""
    # 解析多种来源设置target
    targetSource = request_data.get("targetSource", "general")
    targetList = []
    
    if targetSource == "project" or targetSource == "scan":
        targetList = await get_target_list(request_data['target'], request_data.get("ignore", ""))
    else:
        target_data = await db.ProjectTargetData.find_one({"id": request_data.get('project', [''])})
        targetList = await get_target_list(target_data.get('target', ''), request_data.get("ignore", ""))
    
    if len(targetList) == 0:
        return ""
    
    taskNum = len(targetList)
    
    if "_id" in request_data:
        del request_data["_id"]
    request_data['taskNum'] = taskNum
    request_data['target'] = "\n".join(targetList)
    request_data['progress'] = 0
    request_data["creatTime"] = get_now_time()
    request_data["endTime"] = ""
    request_data["status"] = 1
    request_data["type"] = request_data.get("targetSource", "scan")
    result = await db.task.insert_one(request_data)
    if result.inserted_id:
        task = asyncio.create_task(create_scan_task(request_data, str(result.inserted_id)))
        running_tasks.add(task)
        task.add_done_callback(lambda t: running_tasks.remove(t))
        return result.inserted_id

async def create_scan_task(request_data, id, stop_to_start=False):
    """创建扫描任务"""
    logger.info(f"[create_scan_task] begin: {id}")
    async for db in get_mongo_db():
        async for redis_con in get_redis_pool():
            request_data["id"] = str(id)
            if request_data['allNode']:
                all_node = await get_node_all(redis_con)
                for node in all_node:
                    if node not in request_data["node"]:
                        request_data["node"].append(node)

            # 如果是暂停之后重新开始的，则不需要删除缓存和填入目标
            if stop_to_start is False:
                # 删除可能存在缓存
                keys_to_delete = [
                    f"TaskInfo:tmp:{id}",
                    f"TaskInfo:{id}",
                    f"TaskInfo:time:{id}",
                ]
                progresskeys = await redis_con.keys(f"TaskInfo:progress:{id}:*")
                keys_to_delete.extend(progresskeys)
                progresskeys = await redis_con.keys(f"duplicates:{id}:*")
                keys_to_delete.extend(progresskeys)
                await redis_con.delete(*keys_to_delete)
                # 原始的target生成target list
                target_list = await get_target_list(request_data['target'], request_data.get("ignore", ""))
                # 将任务目标插入redis中
                await redis_con.lpush(f"TaskInfo:{id}", *target_list)
            # 获取模板数据
            template_data = await get_task_data(db, request_data, id)
            # 分发任务
            for name in request_data["node"]:
                await redis_con.rpush(f"NodeTask:{name}", json.dumps(template_data))
            logger.info(f"[create_scan_task] end: {id}")
            return True

async def scheduler_scan_task(id, tp):
    """调度扫描任务"""
    logger.info(f"Scheduler scan {id}")
    async for db in get_mongo_db():
        next_time = scheduler.get_job(id).next_run_time
        formatted_time = next_time.strftime("%Y-%m-%d %H:%M:%S")
        time_now = get_now_time()
        update_document = {
            "$set": {
                "lastTime": time_now,
                "nextTime": formatted_time
            }
        }
        await db.ScheduledTasks.update_one({"id": id}, update_document)
        doc = await db.ScheduledTasks.find_one({"id": id})
        doc["name"] = doc["name"] + f"-{doc.get('targetSource', 'None')}-" + time_now
        await insert_task(doc, db)

async def get_page_monitoring_time():
    """获取页面监控时间"""
    async for db in get_mongo_db():
        result = await db.ScheduledTasks.find_one({"id": "page_monitoring"})
        time = result['hour']
        flag = result['state']
        return time, flag

async def create_page_monitoring_task():
    """创建页面监控任务"""
    logger.info("create_page_monitoring_task")
    async for db in get_mongo_db():
        async for redis in get_redis_pool():
            name_list = []
            result = await db.ScheduledTasks.find_one({"id": "page_monitoring"})
            next_time = scheduler.get_job("page_monitoring").next_run_time
            formatted_time = next_time.strftime("%Y-%m-%d %H:%M:%S")
            update_document = {
                "$set": {
                    "lastTime": get_now_time(),
                    "nextTime": formatted_time
                }
            }
            await db.ScheduledTasks.update_one({"_id": result['_id']}, update_document)
            if result['allNode']:
                tmp = await get_redis_online_data(redis)
                name_list += tmp
            else:
                name_list += result['node']
            targetList = await get_page_monitoring_data(db, False)
            if len(targetList) == 0:
                return
            await redis.delete(f"TaskInfo:page_monitoring")
            await redis.lpush(f"TaskInfo:page_monitoring", *targetList)
            add_redis_task_data = {
                "ID": 'page_monitoring',
                "type": "page_monitoring"
            }
            for name in name_list:
                await redis.rpush(f"NodeTask:{name}", json.dumps(add_redis_task_data))

async def insert_scheduled_tasks(request_data, db, update=False, id=""):
    """插入定时任务"""
    cycle_type = request_data['cycleType']
    if cycle_type == "":
        return
    task_id = ""
    if update is False:
        result = await db.ScheduledTasks.insert_one(request_data)
        if result.inserted_id:
            task_id = str(result.inserted_id)
        else:
            return
    else:
        task_id = id
    week = request_data.get("week", 1)
    day = int(request_data.get("day", 1))
    hour = int(request_data.get("hour", 0))
    minute = int(request_data.get("minute", 0))
    if cycle_type == "daily":
        # 每天固定时间执行
        scheduler.add_job(
            scheduler_scan_task, 'cron',
            hour=hour, minute=minute,
            args=[str(task_id), "scan"],
            id=task_id, jobstore='mongo'
        )
    elif cycle_type == "ndays":
        # 每 N 天执行一次
        scheduler.add_job(
            scheduler_scan_task, 'interval',
            days=day, hours=hour, minutes=minute,
            args=[str(task_id), "scan"],
            id=task_id, jobstore='mongo'
        )
    elif cycle_type == "nhours":
        # 每 N 小时执行一次
        scheduler.add_job(
            scheduler_scan_task, 'interval',
            hours=hour, minutes=minute,
            args=[str(task_id), "scan"],
            id=task_id, jobstore='mongo'
        )
    elif cycle_type == "weekly":
        # 每星期几执行一次
        scheduler.add_job(
            scheduler_scan_task, 'cron',
            day_of_week=week,
            hour=hour, minute=minute,
            args=[str(task_id), "scan"],
            id=task_id, jobstore='mongo'
        )
    elif cycle_type == "monthly":
        # 每月第几天固定时间执行
        scheduler.add_job(
            scheduler_scan_task, 'cron',
            day=day, hour=hour, minute=minute,
            args=[str(task_id), "scan"],
            id=task_id, jobstore='mongo'
        )
    next_time = scheduler.get_job(str(task_id)).next_run_time
    formatted_time = next_time.strftime("%Y-%m-%d %H:%M:%S")
    update_document = {
        "$set": {
            "lastTime": "",
            "nextTime": formatted_time,
            "id": str(task_id)
        }
    }
    await db.ScheduledTasks.update_one({"_id": ObjectId(task_id)}, update_document)
    return

# =============================================================================
# 项目任务处理
# =============================================================================

def get_before_last_dash(s: str) -> str:
    """获取最后一个短横线前的内容"""
    index = s.rfind('-')  # 查找最后一个 '-' 的位置
    if index != -1:
        return s[:index]  # 截取从开头到最后一个 '-' 前的内容
    return s  # 如果没有 '-'，返回原字符串

async def handle_project_scheduler_task(project_data, project_id, scheduled_tasks, hour):
    """处理项目的定时任务"""
    if scheduled_tasks:
        # 添加定时任务
        add_job(scheduler_scan_task, 'interval', hours=hour, args=[project_id, "project"],
                id=project_id, jobstore='mongo')
        
        # 获取下次运行时间
        job = get_job(project_id)
        if job:
            next_time = job.next_run_time
            formatted_time = next_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # 保存到ScheduledTasks集合
            async for db in get_mongo_db():
                scheduled_data = {
                    "name": project_data.get("name", ""),
                    "state": True,
                    "type": "project",
                    "lastTime": "",
                    "nextTime": formatted_time,
                    "id": project_id,
                    "target": project_data.get("target", ""),
                    "node": project_data.get("node", []),
                    "hour": hour,
                    "allNode": project_data.get("allNode", False),
                    "duplicates": project_data.get("duplicates", ""),
                    "template": project_data.get("template", ""),
                    "ignore": project_data.get("ignore", ""),
                    "tag": project_data.get("tag", "")
                }
                await db.ScheduledTasks.insert_one(scheduled_data)
            return True
    return False

async def remove_project_scheduler_task(project_id):
    """移除项目的定时任务"""
    # 移除调度器中的任务
    job = get_job(project_id)
    if job:
        remove_job(project_id)
    
    # 删除数据库中的定时任务记录
    async for db in get_mongo_db():
        await db.ScheduledTasks.delete_many({"id": project_id})

async def update_project_scheduler_task(project_data, project_id, scheduled_tasks, hour):
    """更新项目的定时任务"""
    # 先移除现有的任务
    await remove_project_scheduler_task(project_id)
    
    # 如果需要定时任务，重新创建
    if scheduled_tasks:
        return await handle_project_scheduler_task(project_data, project_id, scheduled_tasks, hour)
    
    return True

async def run_project_task_now(project_data, project_id):
    """立即运行项目任务"""
    time_now = get_now_time()
    task_data = project_data.copy()
    task_data["name"] = task_data.get("name", "") + "-project-" + time_now
    
    async for db in get_mongo_db():
        await insert_task(task_data, db)

async def process_project_target_list(target, ignore=""):
    """处理项目目标列表，返回根域名列表"""
    root_domains = []
    target_list = await get_target_list(target, ignore)
    
    for tg in target_list:
        if "CMP:" in tg or "ICP:" in tg or "APP:" in tg or "APP-ID:" in tg:
            root_domain = tg.replace("CMP:", "").replace("ICP:", "").replace("APP:", "").replace("APP-ID:", "")
            if "ICP:" in tg:
                root_domain = get_before_last_dash(root_domain)
        else:
            root_domain = get_root_domain(tg)
        
        if root_domain not in root_domains:
            root_domains.append(root_domain)
    
    return root_domains

async def scheduler_project(id):
    """废弃的项目调度函数（保留用于兼容性）"""
    logger.warning(f"scheduler_project is deprecated, project id: {id}")
    # 原来的代码被注释，这里只是一个占位符
    pass 