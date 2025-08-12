# -------------------------------------
# @file      : handler.py
# @author    : Autumn
# @contact   : rainy-autumn@outlook.com
# @time      : 2024/10/29 21:00
# -------------------------------------------
import re
import json
import zlib
from pathlib import Path
from datetime import datetime
from bson.objectid import ObjectId
from pymongo import UpdateOne
import asyncio

from core.db import get_mongo_db
from core.util import get_root_domain
from loguru import logger


async def update_project(root_domain, project_id, change=False):
    asset_collection_list = {
                        'asset': ["url", "host", "ip"],
                        'subdomain': ["host", "ip"],
                        'DirScanResult': ["url"],
                        'vulnerability': ["url"],
                        'SubdoaminTakerResult': ["input"],
                        'PageMonitoring': ["url"],
                        'SensitiveResult': ["url"],
                        'UrlScan': ["input"],
                        'crawler': ["url"],
                        'RootDomain': ['domain', 'icp', 'company'],
                        'app': ['name', 'bundleID', 'company', 'icp'],
                        'mp': ['company', 'icp']
    }
    async for db in get_mongo_db():
        for a in asset_collection_list:
            if change:
                await asset_update_project(root_domain, asset_collection_list[a], a, db, project_id)
            else:
                await asset_add_project(root_domain, a, db, project_id)


async def asset_add_project(root_domain, doc_name, db, project_id):
    # 构建查询条件
    if doc_name == "RootDomain":
        regex_patterns = [f"^{re.escape(item)}" for item in root_domain]
        query = {
                    "$or": [
                        {"domain": {"$in": root_domain}},
                        {"company": {"$in": root_domain}},
                        {"icp": {"$regex": "|".join(regex_patterns), "$options": "i"}}
                    ]
                }
    elif doc_name == "app":
        regex_patterns = [f"^{re.escape(item)}" for item in root_domain]
        query = {
            "$or": [
                {"name": {"$in": root_domain}},
                {"bundleID": {"$in": root_domain}},
                {"company": {"$in": root_domain}},
                {"icp": {"$regex": "|".join(regex_patterns), "$options": "i"}},
            ]
        }
    elif doc_name == "mp":
        regex_patterns = [f"^{re.escape(item)}" for item in root_domain]
        query = {
            "$or": [
                {"company": {"$in": root_domain}},
                {"icp": {"$regex": "|".join(regex_patterns), "$options": "i"}}
            ]
        }
    else:
        query = {
            "rootDomain": {"$in": root_domain}
        }
    update_query = {
        "$set": {
            "project": project_id
        }
    }
    result = await db[doc_name].update_many(query, update_query)
    # 打印更新的文档数量
    logger.info(f"Updated {doc_name} {result.modified_count} documents")


async def asset_update_project(root_domain, db_key, doc_name, db, project_id):
    # 获取项目当前的root_domains
    current_project = await db.project.find_one({"_id": ObjectId(project_id)}, {"root_domains": 1})
    if not current_project:
        logger.error(f"Project {project_id} not found")
        return
    
    old_root_domains = current_project.get("root_domains", [])
    new_root_domains = root_domain
    
    # 计算需要移除的域名（在旧列表中但不在新列表中）
    domains_to_remove = [domain for domain in old_root_domains if domain not in new_root_domains]
    # 计算需要添加的域名（在新列表中但不在旧列表中）
    domains_to_add = [domain for domain in new_root_domains if domain not in old_root_domains]
    
    # 如果有需要移除的域名，清空这些域名对应的资产的project字段
    if domains_to_remove:
        if doc_name == "RootDomain":
            regex_patterns = [f"^{re.escape(item)}" for item in domains_to_remove]
            remove_query = {
                "$and": [
                    {"project": project_id},
                    {
                        "$or": [
                            {"domain": {"$in": domains_to_remove}},
                            {"company": {"$in": domains_to_remove}},
                            {"icp": {"$regex": "|".join(regex_patterns), "$options": "i"}}
                        ]
                    }
                ]
            }
        elif doc_name == "app":
            regex_patterns = [f"^{re.escape(item)}" for item in domains_to_remove]
            remove_query = {
                "$and": [
                    {"project": project_id},
                    {
                        "$or": [
                            {"name": {"$in": domains_to_remove}},
                            {"bundleID": {"$in": domains_to_remove}},
                            {"company": {"$in": domains_to_remove}},
                            {"icp": {"$regex": "|".join(regex_patterns), "$options": "i"}}
                        ]
                    }
                ]
            }
        elif doc_name == "mp":
            regex_patterns = [f"^{re.escape(item)}" for item in domains_to_remove]
            remove_query = {
                "$and": [
                    {"project": project_id},
                    {
                        "$or": [
                            {"company": {"$in": domains_to_remove}},
                            {"icp": {"$regex": "|".join(regex_patterns), "$options": "i"}}
                        ]
                    }
                ]
            }
        else:
            remove_query = {
                "$and": [
                    {"project": project_id},
                    {"rootDomain": {"$in": domains_to_remove}}
                ]
            }
        
        update_query = {
            "$set": {
                "project": ""
            }
        }
        result = await db[doc_name].update_many(remove_query, update_query)
        logger.info(f"Removed {doc_name} {result.modified_count} documents from project")
    
    # 如果有需要添加的域名，将这些域名对应的资产分配到项目
    if domains_to_add:
        await asset_add_project(domains_to_add, doc_name, db, project_id)


async def delete_asset_project(db, collection, project_id):
    try:
        # 直接使用批量更新操作，减少单独更新的次数
        query = {"project": project_id}
        update = {"$set": {"project": ""}}

        result = await db[collection].update_many(query, update)

        logger.info(f"Matched {result.matched_count}, Modified {result.modified_count} documents.")
    except Exception as e:
        logger.error(f"delete_asset_project error: {e}")


async def delete_asset_project_handler(project_id):
    async for db in get_mongo_db():
        # 与update_project函数保持一致的资产集合列表
        asset_collection_list = ['asset', 'subdomain', 'DirScanResult', 'vulnerability', 'SubdoaminTakerResult',
                                 'PageMonitoring', 'SensitiveResult', 'UrlScan', 'crawler', 'RootDomain', 'app', 'mp']
        for c in asset_collection_list:
            await delete_asset_project(db, c, project_id)


async def parse_uploaded_file(content: bytes, filename: str):
    """解析上传的文件内容（支持.json和.dat压缩格式）"""
    try:
        # 处理压缩文件
        if Path(filename).suffix.lower() == ".dat":
            flatedict = bytes(', ":'.encode())
            content = zlib.decompressobj(-15, zdict=flatedict).decompress(content).decode()
        else:
            content = content.decode()
        
        # 解析JSON
        return [json.loads(line) for line in content.splitlines() if line.strip()]
    except Exception as e:
        logger.error(f"解析文件错误: {str(e)}")
        return []


async def process_scan_results(results: list, project_id: str, project_name: str, filename: str):
    """处理扫描结果并批量插入数据库"""
    if len(results) < 2:
        logger.warning("没有有效结果需要处理")
        return
    
    async for db in get_mongo_db():
        try:
            # 处理实际结果（跳过配置项）
            scan_results = results[1:-1] if len(results) > 2 else results[1:]
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            task_name = f"{project_name}-upload-{filename}-{now}"
            
            asset_ops = []
            vuln_ops = []
            
            for result in scan_results:
                # 跳过ICMP结果
                if result.get("port") == "icmp":
                    continue
                
                # 提取基础数据
                ip = result.get("ip", "")
                host = result.get("host", ip)
                port = str(result.get("port", ""))
                protocol = result.get("protocol", "http")
                url = f"{protocol}://{ip}:{port}"
                
                # 构建资产文档
                asset_doc = {
                    "project": project_id,
                    "taskName": task_name,
                    "rootDomain": host or ip,
                    "time": now,
                    "ip": ip,
                    "host": ip,
                    "port": port,
                    "url": url,
                    "type": protocol,
                    "service": protocol,
                    "statuscode": int(result.get("status", 0)) if str(result.get("status", "")).isdigit() else 0,
                    "title": result.get("title", ""),
                    "technologies": extract_scan_technologies(result.get("frameworks", {})),
                    "metadata": json.dumps(result.get("frameworks", {})),
                    "iconcontent": "",
                    "tags": [],
                    "screenshot": "",
                    "rawheaders": "",
                    "webServer": result.get("midware", "")
                }
                
                asset_ops.append(
                    UpdateOne(
                        {"ip": ip, "port": port, "project": project_id},
                        {"$set": asset_doc},
                        upsert=True
                    )
                )
                
                # 处理漏洞信息
                for vuln_name, vuln_detail in result.get("vulns", {}).items():
                    vuln_ops.append(
                        UpdateOne(
                            {"url": url, "vulname": vuln_name, "project": project_id},
                            {"$set": {
                                "project": project_id,
                                "taskName": task_name,
                                "rootDomain": host or ip,
                                "time": now,
                                "url": url,
                                "vulname": vuln_name,
                                "vulnid": "",
                                "matched": vuln_detail.get("payload", ""),
                                "request": str(vuln_detail.get("detail", "")),
                                "response": "",
                                "level": vuln_detail.get("severity", ""),
                                "status": 1,
                                "tags": []
                            }},
                            upsert=True
                        )
                    )
            
            # 批量处理资产和漏洞
            results_summary = []
            if asset_ops:
                result = await db.asset.bulk_write(asset_ops, ordered=False)
                results_summary.append(f"资产: {result.upserted_count + result.modified_count}条")
            
            if vuln_ops:
                result = await db.vulnerability.bulk_write(vuln_ops, ordered=False)
                results_summary.append(f"漏洞: {result.upserted_count + result.modified_count}条")
                
            if results_summary:
                logger.info(f"处理完成 {filename}: {', '.join(results_summary)}")
                
        except Exception as e:
            logger.error(f"处理扫描结果错误: {str(e)}")


def extract_scan_technologies(frameworks: dict) -> list:
    """从frameworks中提取技术栈信息"""
    if not frameworks:
        return []
    
    technologies = []
    for name, detail in frameworks.items():
        if isinstance(detail, dict):
            version = detail.get("version", "")
            tech = f"{name}:{version}" if version else name
        else:
            tech = str(name)
        technologies.append(tech)
    
    return technologies


async def update_project_count():
    """更新项目资产数量统计"""
    async for db in get_mongo_db():
        cursor = db.project.find({}, {"_id": 0, "id": {"$toString": "$_id"}})
        results = await cursor.to_list(length=None)

        async def update_count(id):
            query = {"project": {"$eq": id}}
            total_count = await db.asset.count_documents(query)
            if total_count != 0:
                update_document = {
                    "$set": {
                        "AssetCount": total_count
                    }
                }
                await db.project.update_one({"_id": ObjectId(id)}, update_document)

        fetch_tasks = [update_count(r['id']) for r in results]
        await asyncio.gather(*fetch_tasks)


def get_before_last_dash(s: str) -> str:
    """获取最后一个短横线前的内容"""
    index = s.rfind('-')  # 查找最后一个 '-' 的位置
    if index != -1:
        return s[:index]  # 截取从开头到最后一个 '-' 前的内容
    return s  # 如果没有 '-'，返回原字符串


async def process_project_target_list(target, ignore=""):
    """处理项目目标列表，返回根域名列表"""
    from api.task.util import get_target_list
    
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



