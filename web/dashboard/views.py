# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import json
import datetime

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.http import require_safe

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.web_utils import top_detections
from lib.cuckoo.core.database import (
    TASK_COMPLETED,
    TASK_DISTRIBUTED,
    TASK_FAILED_ANALYSIS,
    TASK_FAILED_PROCESSING,
    TASK_FAILED_REPORTING,
    TASK_PENDING,
    TASK_RECOVERED,
    TASK_REPORTED,
    TASK_RUNNING,
    Database,
)

# For MongoDB or Elasticsearch queries
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
import os

repconf = Config("reporting")
if os.path.exists(os.path.join(CUCKOO_ROOT, "conf", "reporting.conf")):
    repconf = Config("reporting")

es_as_db = repconf.elasticsearchdb.enabled
mongodb = repconf.mongodb.enabled

if mongodb:
    from pymongo import MongoClient
    mongo_db = repconf.mongodb.get("db", "cuckoo")
    client = MongoClient(
                host=repconf.mongodb.get("host", "127.0.0.1"),
                port=repconf.mongodb.get("port", 27017),
                username=repconf.mongodb.get("username"),
                password=repconf.mongodb.get("password"),
                authSource=repconf.mongodb.get("authsource", "cuckoo"),
                tlsCAFile=repconf.mongodb.get("tlscafile", None),
                connect=False,
            )
    db = client[mongo_db]
elif es_as_db:
    from elasticsearch import Elasticsearch

    es = Elasticsearch(
        hosts=[
            {
                "host": settings.ELASTIC_HOST,
                "port": settings.ELASTIC_PORT,
            }
        ],
        timeout=60,
    )


# Conditional decorator for web authentication
class conditional_login_required:
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if settings.ANON_VIEW:
            return func
        if not self.condition:
            return func
        return self.decorator(func)


def format_number_with_space(number):
    return f"{number:,}".replace(",", " ")


def get_ml_detection_stats():
    """
    Collect statistics about ML detection from the last 7 days.
    Returns data formatted for the ECharts chart.
    """
    stats = {
        "dates": [],
        "malicious": [],
        "clean": [],
        "other": []
    }
    
    # Get data for the last 7 days
    today = datetime.datetime.now()
    date_range = []
    for i in range(6, -1, -1):
        date_range.append((today - datetime.timedelta(days=i)).strftime("%Y-%m-%d"))
    
    stats["dates"] = date_range
        
    for date_str in date_range:
        date_start = datetime.datetime.strptime(date_str, "%Y-%m-%d")
        date_end = date_start + datetime.timedelta(days=1)
        
        malicious_count = 0
        clean_count = 0
        other_count = 0
        
        if mongodb:
            # MongoDB query for ML detection statistics for this day
            query = {
                "info.started": {
                    "$gte": date_start.strftime("%Y-%m-%d 00:00:00"),
                    "$lt": date_end.strftime("%Y-%m-%d 00:00:00")
                },
                "ml_detection": {"$exists": True}
            }
            
            results = db.analysis.find(query)
            for result in results:
                ml_detection = result.get("ml_detection", {})
                if not ml_detection:
                    continue
                    
                # Check any model's classification
                has_malicious = False
                has_clean = False
                
                for model, predictions in ml_detection.items():
                    if predictions.get("class") == "malicious":
                        has_malicious = True
                    elif predictions.get("class") == "clean":
                        has_clean = True
                
                if has_malicious:
                    malicious_count += 1
                elif has_clean:
                    clean_count += 1
                else:
                    other_count += 1
                    
        elif es_as_db:
            # ElasticSearch query for ML detection statistics for this day
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "info.started": {
                                        "gte": date_start.strftime("%Y-%m-%d 00:00:00"),
                                        "lt": date_end.strftime("%Y-%m-%d 00:00:00")
                                    }
                                }
                            },
                            {
                                "exists": {
                                    "field": "ml_detection"
                                }
                            }
                        ]
                    }
                },
                "size": 10000
            }
            
            try:
                results = es.search(index="analysis-*", body=query)["hits"]["hits"]
                for result in results:
                    ml_detection = result["_source"].get("ml_detection", {})
                    if not ml_detection:
                        continue
                        
                    # Check any model's classification
                    has_malicious = False
                    has_clean = False
                    
                    for model, predictions in ml_detection.items():
                        if predictions.get("class") == "malicious":
                            has_malicious = True
                        elif predictions.get("class") == "clean":
                            has_clean = True
                    
                    if has_malicious:
                        malicious_count += 1
                    elif has_clean:
                        clean_count += 1
                    else:
                        other_count += 1
                        
            except Exception as e:
                print(f"Error querying Elasticsearch: {e}")
                
        stats["malicious"].append(malicious_count)
        stats["clean"].append(clean_count)
        stats["other"].append(other_count)
        
    return stats


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request):
    db = Database()

    report = dict(
        total_samples=format_number_with_space(db.count_samples()),
        total_tasks=format_number_with_space(db.count_tasks()),
        states_count={},
        estimate_hour=None,
        estimate_day=None,
    )

    states = (
        TASK_PENDING,
        TASK_RUNNING,
        TASK_DISTRIBUTED,
        TASK_COMPLETED,
        TASK_RECOVERED,
        TASK_REPORTED,
        TASK_FAILED_ANALYSIS,
        TASK_FAILED_PROCESSING,
        TASK_FAILED_REPORTING,
    )

    for state in states:
        report["states_count"][state] = db.count_tasks(state)

    # For the following stats we're only interested in completed tasks.
    tasks = db.count_tasks(status=TASK_COMPLETED)
    tasks += db.count_tasks(status=TASK_REPORTED)

    data = {"title": "Dashboard", "report": {}}

    if tasks:
        # Get the time when the first task started and last one ended.
        started, completed = db.minmax_tasks()

        # It has happened that for unknown reasons completed and started were
        # equal in which case an exception is thrown, avoid this.
        if started and completed and int(completed - started):
            hourly = 60 * 60 * tasks / (completed - started)
        else:
            hourly = 0

        report["estimate_hour"] = format_number_with_space(int(hourly))
        report["estimate_day"] = format_number_with_space(int(24 * hourly))
        report["top_detections"] = top_detections()
        
        # Add ML detection statistics
        ml_detection_stats = get_ml_detection_stats()
        report["ml_detection_stats"] = json.dumps(ml_detection_stats)

        data["report"] = report
    return render(request, "dashboard/index.html", data)
