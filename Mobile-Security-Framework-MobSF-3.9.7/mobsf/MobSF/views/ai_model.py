import json
from django.http import JsonResponse
from django.core.files.storage import default_storage
import numpy as np
import joblib
from androguard.misc import AnalyzeAPK
from django.conf import settings
import os
from decouple import config
import os
import base64
import requests

model_filename = settings.MODEL_FILENAME
vectorizer_filename = settings.VECTORIZER_FILENAME

clf = joblib.load(model_filename)
vectorizer = joblib.load(vectorizer_filename)

K = 500
api_key = config('APIKEY')

def extract_function_signature(apk_path):
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        function_signature = []
        for meth_analysis in dx.get_methods():
            if meth_analysis.is_external():
                continue
            if len(meth_analysis.get_xref_to()) == 0:
                continue
            api_list = []
            for _, call, _ in meth_analysis.get_xref_to():
                if call.is_external():
                    api_list.append(call.name)
            if api_list:
                function_signature.append(" ".join(api_list))
        return " ".join(function_signature)
    except Exception as e:
        print(f"Error analyzing {apk_path}: {e}")
        return ""

def analyze_apk(file_path):

    new_app_function_signature = extract_function_signature(file_path)
    if new_app_function_signature:
        new_app_tfidf = vectorizer.transform([new_app_function_signature]).toarray()
        top_k_new_app_indices = np.argsort(new_app_tfidf, axis=1)[:, -K:]
        new_app_tfidf_top_k = np.zeros((1, K))
        new_app_tfidf_top_k[0] = new_app_tfidf[0, top_k_new_app_indices[0]]
        new_app_prediction = clf.predict(new_app_tfidf_top_k)
        return new_app_prediction[0]
    else:
        return "无法提取函数签名"




def encode_image(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

def encode_image(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

def chatGPT(directory_paths):
    content = [
        {
            "type": "text",
            "text": "请根据截图识别app的类别，只能选涉黄涉诈还是涉赌，直接告诉我最可能的结果，不要说其他话"
        }
    ]

    for directory_path in directory_paths:
        base64_image = encode_image(directory_path)
        content.append({
            "type": "image_url",
            "image_url": f"data:image/jpeg;base64,{base64_image}"
        })

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    payload = {
        "model": "gpt-4-v",
        "messages": [
            {
                "role": "user",
                "content": content
            }
        ],
        "max_tokens": 300
    }

    response = requests.post("https://api1.zhtec.xyz/v1/chat/completions", headers=headers, json=payload)
    for line in response.iter_lines():
        if line:
            decoded_line = line.decode('utf-8')
            response_data = json.loads(decoded_line)
            # 提取分类结果
            result = response_data['choices'][0]['message']['content']
            return result