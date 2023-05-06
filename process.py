from googleapiclient import discovery
import googleapiclient
import json
import httplib2
import time
import re
import requests
import concurrent.futures

API_KEY = 'AIzaSyC_P6rt8MeHmRSAPmZqo4j5zLwNaJinMvo'

# 设置代理
proxy_info = httplib2.ProxyInfo(
    proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # 使用HTTP代理
    proxy_host='127.0.0.1',  # 代理服务器地址
    proxy_port=7890,  # 代理服务器端口
)

http_obj = httplib2.Http(proxy_info=proxy_info)

client = discovery.build(
  "commentanalyzer",
  "v1alpha1",
  developerKey=API_KEY,
  discoveryServiceUrl="https://commentanalyzer.googleapis.com/$discovery/rest?version=v1alpha1",
  static_discovery=False,
#   http=http_obj,
)

analyze_request = {
  'comment': {'text': ""},
  'requestedAttributes': {'TOXICITY': {}}
}
    
cities = [
    "北京", "天津", "上海", "重庆", "河北", "山西", "辽宁", "吉林", "黑龙江",
    "江苏", "浙江", "安徽", "福建", "江西", "山东", "河南", "湖北", "湖南",
    "广东", "海南", "四川", "贵州", "云南", "陕西", "甘肃", "青海", "内蒙古", 
    "广西", "西藏", "宁夏", "新疆", "中国香港", "澳门"
]

keyword_url = "http://api.pullword.com/get.php?source={}&param1=0.9&param2=1"

def evaluate_malice(comment: str):
    try:
        global analyze_request, client
        time.sleep(1)
        analyze_request["comment"]["text"] = comment
        response = client.comments().analyze(body=analyze_request).execute()
        malice = response["attributeScores"]["TOXICITY"]["spanScores"][0]["score"]["value"]
        print(comment, malice)
        return malice
    except (ConnectionResetError, googleapiclient.errors.HttpError):
        return None
    
def divide_level(malice: float):
    # level 1
    if malice <= 0.3:
        return 1
    # level 2
    elif malice <= 0.4:
        return 2
    # level 3
    return 3

def search_malicious_word(sentence: str):
    response = requests.get(url=keyword_url.format(sentence))
    lines = response.text.split("\n")
    # 提取冒号前的词语，并过滤无效词
    words = [line.split(":")[0] for line in lines if line.strip() and line.strip() != '\r']
    result = []
    for word in words:
        malice = evaluate_malice(word)
        if malice and malice > 0.3:
            print(word, malice)
            result.append(word)
    # 返回句子中的恶意词列表
    print(result)
    return result


def json_process(json_data: dict):
    new_json_data = {"keyword": {}}

    for city in cities:
        new_json_data[city] = {"total": 0,
                               "level_1": 0,
                               "level_2": 0,
                               "level_3": 0,
                               "ratio": 0.0,
                               "comments_1": {},
                               "comments_2": {},
                               "comments_3": {}}

    for key in json_data:
        infos = json_data[key]
        text = infos["text"]
        like = infos["like"]
        time = infos["time"]
        city = infos["source"]
        if city in cities:
            malice = evaluate_malice(text)
            if malice:
                level = divide_level(malice)
                new_json_data[city]["total"] += 1
                new_json_data[city][f"level_{level}"] += 1
                new_json_data[city][f"comments_{level}"][text] = {"like": like, "time": time}
                # 对于2,3级恶意的句子 检测其中的恶意词
                if level > 1:
                    malicious_words = search_malicious_word(text)
                    for malicious_word in malicious_words:
                        if malicious_word not in new_json_data["keyword"]:
                            new_json_data["keyword"][malicious_word] = 1
                        else:
                            new_json_data["keyword"][malicious_word] += 1
    
    for city in cities:
        try:
            new_json_data[city]["ratio"] = (new_json_data[city]["level_2"] * 0.5 + new_json_data[city]["level_3"]) / \
                (new_json_data[city]["level_1"] + new_json_data[city]["level_2"] + new_json_data[city]["level_3"])
        except ZeroDivisionError:
            new_json_data[city]["ratio"] = 0

    new_json_data["keyword"] = dict(sorted(new_json_data["keyword"].items(), key=lambda item: item[1], reverse=True))
        
    # with open(f"test.json", "w", encoding='utf-8') as out_file:
    #     json.dump(new_json_data, out_file, ensure_ascii=False, indent=4)

    return new_json_data            

# if __name__ == '__main__':
#     topic = "上海科技大学虐猫"
#     with open(f"./resources/comments/{topic}.json", "r", encoding='utf-8') as file:
#         crawl_data = json.load(file)
#     json_process(crawl_data)

