import json
import crawl
import process
from flask import Flask, jsonify
from flask_cors import CORS
import itertools

app = Flask(__name__)
CORS(app)

@app.route('/<topic>')
def back_end(topic):
    if topic == "favicon.ico":
        return jsonify(message="None")
    
    # with open(f"./resources/comments/{topic}.json", "r", encoding='utf-8') as file:
    #     crawl_data = json.load(file)

    crawl_data = crawl.topic_crawl(key=topic, num=10)
    first_ten = dict(itertools.islice(crawl_data.items(), 10))
    result_data = process.json_process(first_ten)
    return jsonify(message=result_data)

if __name__ == '__main__':
    app.run()
